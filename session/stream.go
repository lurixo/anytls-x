package session

import (
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/anytls/sing-anytls/pipe"
)

type Stream struct {
	id uint32

	sess *Session

	pipeR         *pipe.PipeReader
	pipeW         *pipe.PipeWriter
	writeDeadline pipe.PipeDeadline

	dieOnce sync.Once
	dieHook func()
	dieErr  atomic.Pointer[error]

	reportOnce sync.Once

	// frameSeq counts data frames sent on this stream.  The first few
	// frames (<= earlyDataFrames) carry the inner TLS handshake; the
	// record shaper splits the inner ClientHello among several records
	// so it no longer appears as a single ~517 B record (the headline
	// TLS-in-TLS signature).  Stream.Write is single-goroutine, but an
	// atomic counter is used for defence in depth.
	frameSeq atomic.Uint32

	// synTimer is the per-stream SYNACK timeout (client only, sid >= 2).
	// Fires if the server does not acknowledge the stream within the deadline.
	// Only closes this stream; may also close session if no SYNACK received.
	synTimer *time.Timer
}

func newStream(id uint32, sess *Session) *Stream {
	s := new(Stream)
	s.id = id
	s.sess = sess
	s.pipeR, s.pipeW = pipe.Pipe()
	s.writeDeadline = pipe.MakePipeDeadline()
	return s
}

func (s *Stream) Read(b []byte) (n int, err error) {
	n, err = s.pipeR.Read(b)
	if n == 0 {
		if ep := s.dieErr.Load(); ep != nil {
			err = *ep
		}
	}
	return
}

func (s *Stream) Write(b []byte) (n int, err error) {
	select {
	case <-s.writeDeadline.Wait():
		return 0, os.ErrDeadlineExceeded
	default:
	}
	if ep := s.dieErr.Load(); ep != nil {
		return 0, *ep
	}
	seq := s.frameSeq.Add(1)
	early := seq <= earlyDataFrames
	n, err = s.sess.writeDataFrameShaped(s.id, b, early)
	return
}

func (s *Stream) Close() error {
	return s.closeWithError(io.ErrClosedPipe)
}

// closeLocally only closes Stream and don't notify remote peer
func (s *Stream) closeLocally() {
	var once bool
	s.dieOnce.Do(func() {
		if s.synTimer != nil {
			s.synTimer.Stop()
		}
		e := error(net.ErrClosed)
		s.dieErr.Store(&e)
		s.pipeR.Close()
		once = true
	})
	if once {
		if s.dieHook != nil {
			s.dieHook()
			s.dieHook = nil
		}
	}
}

func (s *Stream) closeWithError(err error) error {
	var once bool
	s.dieOnce.Do(func() {
		if s.synTimer != nil {
			s.synTimer.Stop()
		}
		s.dieErr.Store(&err)
		s.pipeR.Close()
		once = true
	})
	if once {
		if s.dieHook != nil {
			s.dieHook()
			s.dieHook = nil
		}
		return s.sess.streamClosed(s.id)
	} else {
		if ep := s.dieErr.Load(); ep != nil {
			return *ep
		}
		return io.ErrClosedPipe
	}
}

func (s *Stream) SetReadDeadline(t time.Time) error {
	return s.pipeR.SetReadDeadline(t)
}

func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.writeDeadline.Set(t)
	return nil
}

func (s *Stream) SetDeadline(t time.Time) error {
	s.SetWriteDeadline(t)
	return s.SetReadDeadline(t)
}

func (s *Stream) LocalAddr() net.Addr {
	if ts, ok := s.sess.conn.(interface {
		LocalAddr() net.Addr
	}); ok {
		return ts.LocalAddr()
	}
	return nil
}

func (s *Stream) RemoteAddr() net.Addr {
	if ts, ok := s.sess.conn.(interface {
		RemoteAddr() net.Addr
	}); ok {
		return ts.RemoteAddr()
	}
	return nil
}

// HandshakeFailure should be called when Server fail to create outbound proxy
func (s *Stream) HandshakeFailure(err error) error {
	var once bool
	s.reportOnce.Do(func() {
		once = true
	})
	if once && err != nil && s.sess.peerVersion.Load() >= 2 {
		f := newFrame(cmdSYNACK, s.id)
		f.data = []byte(err.Error())
		if _, err := s.sess.writeControlFrame(f); err != nil {
			return err
		}
	}
	return nil
}

// HandshakeSuccess should be called when Server success to create outbound proxy
func (s *Stream) HandshakeSuccess() error {
	var once bool
	s.reportOnce.Do(func() {
		once = true
	})
	if once && s.sess.peerVersion.Load() >= 2 {
		if _, err := s.sess.writeControlFrame(newFrame(cmdSYNACK, s.id)); err != nil {
			return err
		}
	}
	return nil
}
