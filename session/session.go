package session

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/anytls/sing-anytls/padding"
	"github.com/anytls/sing-anytls/util"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
)

type Session struct {
	conn     net.Conn
	connLock sync.Mutex

	streams    map[uint32]*Stream
	streamId   atomic.Uint32
	streamLock sync.RWMutex

	// activeStreams counts streams currently open on this session. It is
	// maintained entirely by the client pool (incremented in Client.openOn,
	// decremented in the stream die hook) and lets the pool multiplex
	// several streams onto one session under the session cap while still
	// returning the session to the idle pool only after its last stream
	// closes. Unused by the server path.
	activeStreams atomic.Int32

	dieOnce sync.Once
	die     chan struct{}
	dieHook func()

	consecutiveSynAckTimeouts atomic.Uint32
	connBroken                atomic.Bool
	// recvBlocked is true while recvLoop is blocked handing a data frame to a
	// slow-reading stream. The link has just delivered a full frame, so it is
	// alive; the heartbeat probe must not treat the stalled response processing
	// as a dead connection and tear the session (and its sibling streams) down.
	recvBlocked atomic.Bool
	// lastHeartRespNano records the time of the most recent cmdHeartResponse
	// only. Liveness is judged on a confirmed request/response round-trip rather
	// than on any inbound frame, so a half-open uplink (downlink still delivering
	// data while our writes never reach the peer) is still detected.
	lastHeartRespNano atomic.Int64

	// pool
	seq       uint64
	idleSince time.Time
	padding   *atomic.TypedValue[*padding.PaddingFactory]
	logger    logger.Logger

	peerVersion atomic.Uint32

	// client
	client      *Client
	isClient    bool
	sendPadding bool
	buffering   bool
	buffer      []byte
	pktCounter  atomic.Uint32

	idleReady     chan struct{}
	idleReadyOnce sync.Once

	// server
	onNewStream func(stream *Stream)
}

func NewClientSession(conn net.Conn, _padding *atomic.TypedValue[*padding.PaddingFactory], logger logger.Logger) *Session {
	s := &Session{
		conn:        conn,
		isClient:    true,
		sendPadding: true,
		padding:     _padding,
		logger:      logger,
	}
	s.die = make(chan struct{})
	s.streams = make(map[uint32]*Stream)
	s.idleReady = make(chan struct{})
	return s
}

func NewServerSession(conn net.Conn, onNewStream func(stream *Stream), _padding *atomic.TypedValue[*padding.PaddingFactory], logger logger.Logger) *Session {
	s := &Session{
		conn:        conn,
		onNewStream: onNewStream,
		padding:     _padding,
		logger:      logger,
	}
	s.die = make(chan struct{})
	s.streams = make(map[uint32]*Stream)
	s.idleReady = make(chan struct{})
	return s
}

func (s *Session) Run() {
	if !s.isClient {
		s.recvLoop()
		return
	}

	settings := util.StringMap{
		"v":           "2",
		"client":      util.Verison,
		"padding-md5": s.padding.Load().Md5,
	}
	f := newFrame(cmdSettings, 0)
	f.data = settings.ToBytes()
	s.buffering = true
	s.writeControlFrame(f)

	go s.recvLoop()
	go s.heartbeatLoop()
}

// IsClosed does a safe check to see if we have shutdown
func (s *Session) IsClosed() bool {
	select {
	case <-s.die:
		return true
	default:
		return false
	}
}

func (s *Session) signalIdleReady() {
	s.idleReadyOnce.Do(func() { close(s.idleReady) })
}

func (s *Session) Close() error {
	var once bool
	s.dieOnce.Do(func() {
		close(s.die)
		once = true
	})
	if once {
		s.signalIdleReady()
		if s.dieHook != nil {
			s.dieHook()
			s.dieHook = nil
		}
		s.streamLock.Lock()
		for _, stream := range s.streams {
			stream.closeLocally()
		}
		s.streams = make(map[uint32]*Stream)
		s.streamLock.Unlock()
		s.conn.SetWriteDeadline(time.Now().Add(-time.Second)) // abort any stuck no-deadline write so connLock is obtainable
		return s.conn.Close()
	} else {
		return io.ErrClosedPipe
	}
}

type synAckTimeoutError struct{}

func (synAckTimeoutError) Error() string   { return "SYNACK timeout" }
func (synAckTimeoutError) Timeout() bool   { return true }
func (synAckTimeoutError) Temporary() bool { return true }

func (s *Session) OpenStream(dieHook func()) (*Stream, error) {
	if s.IsClosed() || s.connBroken.Load() {
		return nil, io.ErrClosedPipe
	}

	sid := s.streamId.Add(1)
	stream := newStream(sid, s)
	stream.dieHook = dieHook

	if sid >= 2 && s.peerVersion.Load() >= 2 {
		stream.synTimer = time.AfterFunc(time.Second*5, func() {
			n := s.consecutiveSynAckTimeouts.Add(1)
			// Reap the whole session on a SYNACK timeout only when this is its
			// SOLE stream (an idle session just reused for this one failed
			// stream, so closing it cannot kill a live sibling), or once
			// consecutive timeouts cross the threshold. A session still carrying
			// other streams (e.g. a live multiplexed long connection) is never
			// torn down on a single slow SYNACK, so a healthy sibling is never
			// dropped. Any received SYNACK resets the counter.
			reap := s.shouldReapOnSynAckTimeout(n)
			if reap {
				// Mark broken before closing the stream so the synchronous
				// streamDieHook reaps the session instead of re-pooling it.
				s.connBroken.Store(true)
			}
			stream.closeWithError(synAckTimeoutError{})
			if reap {
				if n >= synAckTimeoutAlertThreshold {
					s.logger.Error("anytls: ", synAckTimeoutAlertThreshold, " consecutive SYNACK timeouts; the server completed its handshake but is no longer acknowledging new streams")
				}
				s.Close()
			}
		})
	}

	s.streamLock.Lock() // register before sending SYN so a fast SYNACK isn't missed
	select {
	case <-s.die:
		s.streamLock.Unlock()
		if stream.synTimer != nil {
			stream.synTimer.Stop()
		}
		return nil, io.ErrClosedPipe
	default:
	}
	s.streams[sid] = stream
	s.streamLock.Unlock()

	if _, err := s.writeControlFrame(newFrame(cmdSYN, sid)); err != nil {
		s.streamLock.Lock()
		delete(s.streams, sid)
		s.streamLock.Unlock()
		if stream.synTimer != nil {
			stream.synTimer.Stop()
		}
		// Return the (now-dead) stream alongside the error. The stream was
		// already registered above, so a writeControlFrame failure on a
		// REUSED session runs Session.Close, which fired this stream's die
		// hook (decrementing activeStreams). openOn inspects the returned
		// stream to avoid a second, double-counting rollback decrement.
		return stream, err
	}

	s.connLock.Lock()
	s.buffering = false
	s.connLock.Unlock()

	return stream, nil
}

func (s *Session) recvLoop() error {
	// defer func() {
	// 	if r := recover(); r != nil {
	// 		logrus.Errorln("[BUG]", r, string(debug.Stack()))
	// 	}
	// }()
	defer s.Close()

	var receivedSettingsFromClient bool
	var hdr rawHeader

	for {
		if s.IsClosed() {
			return io.ErrClosedPipe
		}
		// read header first
		if _, err := io.ReadFull(s.conn, hdr[:]); err == nil {
			sid := hdr.StreamID()
			switch hdr.Cmd() {
			case cmdPSH:
				if hdr.Length() > 0 {
					buffer := buf.Get(int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, buffer); err == nil {
						s.streamLock.RLock()
						stream, ok := s.streams[sid]
						s.streamLock.RUnlock()
						if ok {
							s.recvBlocked.Store(true)
							stream.pipeW.Write(buffer)
							s.recvBlocked.Store(false)
						}
						buf.Put(buffer)
					} else {
						buf.Put(buffer)
						return err
					}
				}
			case cmdSYN:
				if !s.isClient && !receivedSettingsFromClient {
					f := newFrame(cmdAlert, 0)
					f.data = []byte("client did not send its settings")
					s.writeControlFrame(f)
					return nil
				}
				s.streamLock.Lock()
				if _, ok := s.streams[sid]; !ok {
					stream := newStream(sid, s)
					s.streams[sid] = stream
					go func() {
						if s.onNewStream != nil {
							s.onNewStream(stream)
						} else {
							stream.Close()
						}
					}()
				}
				s.streamLock.Unlock()
			case cmdSYNACK:
				s.consecutiveSynAckTimeouts.Store(0)
				s.streamLock.RLock()
				synStream, synOk := s.streams[sid]
				s.streamLock.RUnlock()
				if synOk && synStream.synTimer != nil {
					synStream.synTimer.Stop()
				}
				if hdr.Length() > 0 {
					buffer := buf.Get(int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, buffer); err != nil {
						buf.Put(buffer)
						return err
					}
					s.streamLock.RLock()
					stream, ok := s.streams[sid]
					s.streamLock.RUnlock()
					if ok {
						stream.closeWithError(fmt.Errorf("remote: %s", string(buffer)))
					}
					buf.Put(buffer)
				}
			case cmdFIN:
				s.streamLock.Lock()
				stream, ok := s.streams[sid]
				delete(s.streams, sid)
				s.streamLock.Unlock()
				if ok {
					stream.closeLocally()
				}
			case cmdWaste:
				if hdr.Length() > 0 {
					buffer := buf.Get(int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, buffer); err != nil {
						buf.Put(buffer)
						return err
					}
					buf.Put(buffer)
				}
			case cmdSettings:
				if hdr.Length() > 0 {
					buffer := buf.Get(int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, buffer); err != nil {
						buf.Put(buffer)
						return err
					}
					if !s.isClient {
						receivedSettingsFromClient = true
						m := util.StringMapFromBytes(buffer)
						paddingF := s.padding.Load()
						if m["padding-md5"] != paddingF.Md5 {
							f := newFrame(cmdUpdatePaddingScheme, 0)
							f.data = paddingF.RawScheme
							_, err = s.writeControlFrame(f)
							if err != nil {
								buf.Put(buffer)
								return err
							}
						}
						// check client's version
						if v, err := strconv.Atoi(m["v"]); err == nil && v >= 2 {
							s.peerVersion.Store(uint32(v))
							// send cmdServerSettings
							f := newFrame(cmdServerSettings, 0)
							f.data = util.StringMap{
								"v": "2",
							}.ToBytes()
							_, err = s.writeControlFrame(f)
							if err != nil {
								buf.Put(buffer)
								return err
							}
						}
					}
					buf.Put(buffer)
				}
			case cmdAlert:
				if hdr.Length() > 0 {
					buffer := buf.Get(int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, buffer); err != nil {
						buf.Put(buffer)
						return err
					}
					if s.isClient {
						s.logger.Error("[Alert from server]", string(buffer))
					}
					buf.Put(buffer)
					return nil
				}
			case cmdUpdatePaddingScheme:
				if hdr.Length() > 0 {
					if hdr.Length() > maxPaddingSchemeLen {
						return fmt.Errorf("padding scheme too large: %d > %d", hdr.Length(), maxPaddingSchemeLen)
					}
					rawScheme := make([]byte, int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, rawScheme); err != nil {
						return err
					}
					if s.isClient {
						if padding.UpdatePaddingScheme(rawScheme, s.padding) {
							s.logger.Debug(fmt.Sprintf("[Update padding succeed] %x\n", md5.Sum(rawScheme)))
						} else {
							s.logger.Warn(fmt.Sprintf("[Update padding failed] %x\n", md5.Sum(rawScheme)))
						}
					}
				}
			case cmdHeartRequest:
				if _, err := s.writeControlFrame(newFrame(cmdHeartResponse, sid)); err != nil {
					return err
				}
			case cmdHeartResponse:
				s.lastHeartRespNano.Store(time.Now().UnixNano())
			case cmdServerSettings:
				if hdr.Length() > 0 {
					buffer := buf.Get(int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, buffer); err != nil {
						buf.Put(buffer)
						return err
					}
					if s.isClient {
						// check server's version
						m := util.StringMapFromBytes(buffer)
						if v, err := strconv.Atoi(m["v"]); err == nil {
							s.peerVersion.Store(uint32(v))
						}
						s.signalIdleReady()
					}
					buf.Put(buffer)
				}
			default:
				// Drain unknown command's payload to keep the stream
				// in sync, instead of silently desynchronizing.
				if hdr.Length() > 0 {
					buffer := buf.Get(int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, buffer); err != nil {
						buf.Put(buffer)
						return err
					}
					buf.Put(buffer)
				}
			}
		} else {
			return err
		}
	}
}

func (s *Session) streamClosed(sid uint32) error {
	if s.IsClosed() {
		return io.ErrClosedPipe
	}
	_, err := s.writeControlFrame(newFrame(cmdFIN, sid))
	s.streamLock.Lock()
	delete(s.streams, sid)
	s.streamLock.Unlock()
	return err
}

func (s *Session) writeDataFrame(sid uint32, data []byte) (int, error) {
	dataLen := len(data)

	buffer := buf.NewSize(dataLen + headerOverHeadSize)
	buffer.WriteByte(cmdPSH)
	binary.BigEndian.PutUint32(buffer.Extend(4), sid)
	binary.BigEndian.PutUint16(buffer.Extend(2), uint16(dataLen))
	buffer.Write(data)
	_, err := s.writeConn(buffer.Bytes())
	buffer.Release()
	if err != nil {
		s.connBroken.Store(true)
		return 0, err
	}

	return dataLen, nil
}

// maxPaddingSchemeLen bounds an incoming cmdUpdatePaddingScheme payload.
// The frame length field is uint16 (so <=64 KB already), but a server the
// client trusts could still push a needlessly large scheme; 16 KB is far
// above any legitimate scheme (the built-in default is ~120 B).
const maxPaddingSchemeLen = 16 * 1024

func (s *Session) writeControlFrame(frame frame) (int, error) {
	dataLen := len(frame.data)
	if dataLen > maxFrameDataLen {
		return 0, fmt.Errorf("control frame data too large: %d > %d", dataLen, maxFrameDataLen)
	}

	buffer := buf.NewSize(dataLen + headerOverHeadSize)
	buffer.WriteByte(frame.cmd)
	binary.BigEndian.PutUint32(buffer.Extend(4), frame.sid)
	binary.BigEndian.PutUint16(buffer.Extend(2), uint16(dataLen))
	buffer.Write(frame.data)

	s.conn.SetWriteDeadline(time.Now().Add(time.Second * 5))

	_, err := s.writeConn(buffer.Bytes())
	buffer.Release()
	if err != nil {
		s.Close()
		return 0, err
	}

	s.conn.SetWriteDeadline(time.Time{})

	return dataLen, nil
}

func (s *Session) writeConn(b []byte) (n int, err error) {
	s.connLock.Lock()
	defer s.connLock.Unlock()

	if s.buffering {
		s.buffer = slices.Concat(s.buffer, b)
		return len(b), nil
	} else if len(s.buffer) > 0 {
		b = slices.Concat(s.buffer, b)
		s.buffer = nil
	}

	// calulate & send padding
	if s.sendPadding {
		pkt := s.pktCounter.Add(1)
		paddingF := s.padding.Load()
		if pkt < paddingF.Stop {
			pktSizes := paddingF.GenerateRecordPayloadSizes(pkt)
			for _, l := range pktSizes {
				remainPayloadLen := len(b)
				if l == padding.CheckMark {
					if remainPayloadLen == 0 {
						break
					} else {
						continue
					}
				}
				if remainPayloadLen > l { // this packet is all payload
					_, err = s.conn.Write(b[:l])
					if err != nil {
						return 0, err
					}
					n += l
					b = b[l:]
				} else if remainPayloadLen > 0 { // this packet contains padding and the last part of payload
					paddingLen := l - remainPayloadLen - headerOverHeadSize
					if paddingLen > 0 {
						padding := make([]byte, headerOverHeadSize+paddingLen)
						padding[0] = cmdWaste
						binary.BigEndian.PutUint32(padding[1:5], 0)
						binary.BigEndian.PutUint16(padding[5:7], uint16(paddingLen))
						b = slices.Concat(b, padding)
					}
					_, err = s.conn.Write(b)
					if err != nil {
						return 0, err
					}
					n += remainPayloadLen
					b = nil
				} else { // this packet is all padding
					padding := make([]byte, headerOverHeadSize+l)
					padding[0] = cmdWaste
					binary.BigEndian.PutUint32(padding[1:5], 0)
					binary.BigEndian.PutUint16(padding[5:7], uint16(l))
					_, err = s.conn.Write(padding)
					if err != nil {
						return 0, err
					}
					b = nil
				}
			}
			// maybe still remain payload to write
			if len(b) == 0 {
				return
			} else {
				n2, err := s.conn.Write(b)
				return n + n2, err
			}
		} else {
			s.sendPadding = false
		}
	}

	return s.conn.Write(b)
}

const writeDeadline = 5 * time.Second

const (
	defaultHeartbeatInterval    = 15 * time.Second
	defaultHeartbeatQuietWindow = 10 * time.Second
	defaultHeartbeatTimeout     = 5 * time.Second
)

// shouldReapOnSynAckTimeout decides whether a per-stream SYNACK timeout should
// tear down the whole session. It reaps only when the timing-out stream is the
// session's sole active stream (activeStreams <= 1) — so no live multiplexed
// sibling can ever be dropped — or when consecutive timeouts reach the alert
// threshold (the peer has stopped acknowledging new streams entirely).
func (s *Session) shouldReapOnSynAckTimeout(consecutive uint32) bool {
	return s.activeStreams.Load() <= 1 || consecutive >= synAckTimeoutAlertThreshold
}

func (s *Session) heartbeatIntervalValue() time.Duration {
	if s.client != nil && s.client.heartbeatInterval > 0 {
		return s.client.heartbeatInterval
	}
	return defaultHeartbeatInterval
}

func (s *Session) heartbeatQuietWindowValue() time.Duration {
	if s.client != nil && s.client.heartbeatQuietWindow > 0 {
		return s.client.heartbeatQuietWindow
	}
	return defaultHeartbeatQuietWindow
}

func (s *Session) heartbeatTimeoutValue() time.Duration {
	if s.client != nil && s.client.heartbeatTimeout > 0 {
		return s.client.heartbeatTimeout
	}
	return defaultHeartbeatTimeout
}

func (s *Session) nextHeartbeatInterval() time.Duration {
	base := int(s.heartbeatIntervalValue() / time.Millisecond)
	jitter := base / 4
	ms := base - jitter + util.FastIntn(2*jitter+1)
	return time.Duration(ms) * time.Millisecond
}

func (s *Session) heartbeatLoop() {
	select {
	case <-s.die:
		return
	case <-s.idleReady:
	}

	for {
		select {
		case <-s.die:
			return
		case <-time.After(s.nextHeartbeatInterval()):
		}

		if !s.heartbeatProbe() {
			return
		}
	}
}

func (s *Session) heartbeatProbe() bool {
	if s.IsClosed() || s.connBroken.Load() {
		return false
	}

	// Skip the active probe only while a recent heart-response confirms the
	// link is healthy in both directions; inbound data alone is not enough.
	last := s.lastHeartRespNano.Load()
	if last != 0 && time.Since(time.Unix(0, last)) < s.heartbeatQuietWindowValue() {
		return true
	}

	s.connLock.Lock()
	buffering := s.buffering
	s.connLock.Unlock()
	if buffering {
		return true
	}

	sentAt := time.Now().UnixNano()
	// Send the probe off the heartbeat goroutine so it can't hang on connLock:
	// a control write only holds connLock for at most writeDeadline, so if the
	// write stays blocked well past that, a stuck no-deadline data write is
	// wedging the connection. Treat that as a dead link instead of waiting out
	// the kernel's TCP timeout. The buffered channel plus Close()'s negative
	// write deadline (which aborts the stuck write and frees connLock) ensure
	// this goroutine always returns rather than leaking.
	writeDone := make(chan error, 1)
	go func() {
		_, err := s.writeControlFrame(newFrame(cmdHeartRequest, 0))
		writeDone <- err
	}()

	select {
	case <-s.die:
		return false
	case err := <-writeDone:
		if err != nil {
			return false
		}
	case <-time.After(writeDeadline + s.heartbeatTimeoutValue()):
		s.connBroken.Store(true)
		s.Close()
		return false
	}

	select {
	case <-s.die:
		return false
	case <-time.After(s.heartbeatTimeoutValue()):
	}

	if s.lastHeartRespNano.Load() < sentAt {
		if s.recvBlocked.Load() {
			return true
		}
		s.connBroken.Store(true)
		s.Close()
		return false
	}

	return true
}
