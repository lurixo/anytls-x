package session

import (
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lurixo/anytls-x/pipe"
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

	// mig holds 0-RTT rail-switch state; non-nil only while migration is
	// negotiated active on the session. A nil mig means every path below
	// behaves exactly like upstream.
	mig *streamMig
}

func newStream(id uint32, sess *Session) *Stream {
	s := new(Stream)
	s.id = id
	s.sess = sess
	s.pipeR, s.pipeW = pipe.Pipe()
	s.writeDeadline = pipe.MakePipeDeadline()
	if sess.migActive {
		s.mig = newStreamMig(s, sess)
	}
	return s
}

func (s *Stream) Read(b []byte) (n int, err error) {
	n, err = s.pipeR.Read(b)
	if n == 0 {
		if ep := s.dieErr.Load(); ep != nil {
			err = *ep
		}
	}
	if n > 0 && s.mig != nil && !s.sess.isClient {
		// Server uplink tap: feed the relayed client->server inner records to
		// the handshake detector. Cheap and stops itself once a verdict is in.
		s.mig.observeServerRead(b[:n])
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
	if sm := s.mig; sm != nil {
		return s.migWrite(sm, b)
	}
	seq := s.frameSeq.Add(1)
	early := seq <= earlyDataFrames
	n, err = s.sess.writeDataFrameShaped(s.id, b, early)
	return
}

// migWrite is the write path while the rail-switch is active, for both sides.
// After the cut-over it writes raw bytes straight onto the dedicated carrier B
// (server downlink, client uplink), serialised under writeMu so concurrent
// writers never interleave a record. Before the cut-over it writes the mux; on
// the server it also feeds the handshake detector and fires the cut-over offer
// once authorised. writeMu serialises against the barrier emitters
// (serverAttachCarrier / maybeClientCutover) so a barrier lands exactly between
// the last mux frame and the first B frame for this stream.
func (s *Stream) migWrite(sm *streamMig, b []byte) (n int, err error) {
	sm.writeMu.Lock()
	defer sm.writeMu.Unlock()
	if bc := sm.bWriteConn; bc != nil {
		return bc.Write(b)
	}
	if !s.sess.isClient {
		sm.observeServerWrite(b)
	}
	seq := s.frameSeq.Add(1)
	early := seq <= earlyDataFrames
	n, err = s.sess.writeDataFrameShaped(s.id, b, early)
	if !s.sess.isClient {
		sm.serverMaybeTrigger()
	}
	return
}

// BeginMigrationPayload marks the point where the anytls stream header (the
// destination address) has been fully consumed and the real payload begins, so
// the server-side migration detector observes only payload bytes — never the
// header (whose leading address-family byte would otherwise be misread as a TLS
// record type). The server's stream acceptor calls this once, right after
// reading the destination. No-op when migration is inactive for this stream.
func (s *Stream) BeginMigrationPayload() {
	if s.mig != nil {
		s.mig.payloadStarted.Store(true)
	}
}

func (s *Stream) Close() error {
	return s.closeWithError(io.ErrClosedPipe)
}

// CloseWrite implements N.WriteCloser. With the rail-switch active and the flow
// already cut over to carrier B, it half-closes B's write direction so the
// migrated byte stream is flushed and ended losslessly (see streamMig.closeWrite)
// instead of being abruptly reset. For every other case — migration inactive
// (s.mig == nil) or a flow that never cut over — it falls back to the full Close
// the sing-box relay would otherwise have called, so the non-migration path is
// byte-for-byte unchanged.
func (s *Stream) CloseWrite() error {
	if s.mig == nil {
		return s.Close()
	}
	return s.mig.closeWrite()
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
		if s.mig != nil {
			s.mig.closeOnStreamEnd()
		}
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
		if s.mig != nil {
			s.mig.closeOnStreamEnd()
		}
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
