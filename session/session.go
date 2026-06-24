package session

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"io"
	"net"
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
	client    *Client
	isClient  bool
	buffering bool
	buffer    []byte

	shaper *RecordShaper

	idleReady     chan struct{}
	idleReadyOnce sync.Once
	// idleLoopOnce keeps the lazy idleLoop start (see maybeStartIdleLoop) single-shot.
	idleLoopOnce sync.Once

	// WINDOW_UPDATE injection: recvBytes, wndUpdateBase and
	// wndUpdateTrigger are only accessed by recvLoop (single goroutine),
	// so no lock is needed.
	recvBytes        int
	wndUpdateBase    int
	wndUpdateTrigger int

	// server
	onNewStream func(stream *Stream)

	// migActive is set once, before any stream is created, when the 0-RTT
	// rail-switch is negotiated active for this session (ANYTLS_MIGRATION=1 on
	// the client, which advertises "mig"=1, and on the server). When false the
	// session behaves exactly like upstream. Streams attach their migration
	// state (Stream.mig) at creation iff this is true.
	migActive bool
	// migRegistry (server only) lets a stream register its pending carrier
	// token so the Service can match an inbound carrier B back to it.
	migRegistry *MigRegistry
	// migMinBulk (server only) is the per-service bulk gate override (0 = use
	// the built-in default); it is handed to each stream's handshake detector.
	migMinBulk int
	// migTLSOnly (server only) restricts migration to TLS flows: opaque flows
	// (UoT-UDP, plaintext …) then stay on the mux instead of bulk-migrating.
	migTLSOnly bool
}

// SetMigRegistry attaches the Service-wide carrier registry to a server
// session. Called once, before Run, only when migration is enabled.
func (s *Session) SetMigRegistry(reg *MigRegistry) {
	s.migRegistry = reg
}

// SetMigMinBulk sets the per-service bulk-gate override for this server
// session's streams. Called once, before Run.
func (s *Session) SetMigMinBulk(n int) {
	s.migMinBulk = n
}

// SetMigTLSOnly restricts this server session's migration to TLS flows. Called
// once, before Run.
func (s *Session) SetMigTLSOnly(v bool) {
	s.migTLSOnly = v
}

func NewClientSession(conn net.Conn, _padding *atomic.TypedValue[*padding.PaddingFactory], logger logger.Logger) *Session {
	s := &Session{
		conn:     conn,
		isClient: true,
		padding:  _padding,
		logger:   logger,
	}
	s.die = make(chan struct{})
	s.streams = make(map[uint32]*Stream)
	s.shaper = newRecordShaper(conn, _padding)
	s.idleReady = make(chan struct{})
	if cfg := _padding.Load().RecordConfig; cfg.WndUpdateInterval > 0 {
		s.wndUpdateBase = cfg.WndUpdateInterval
		s.wndUpdateTrigger = nextWndInterval(s.wndUpdateBase)
	}
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
	s.shaper = newRecordShaper(conn, _padding)
	s.idleReady = make(chan struct{})
	if cfg := _padding.Load().RecordConfig; cfg.WndUpdateInterval > 0 {
		s.wndUpdateBase = cfg.WndUpdateInterval
		s.wndUpdateTrigger = nextWndInterval(s.wndUpdateBase)
	}
	return s
}

func (s *Session) Run() {
	s.maybeStartIdleLoop()

	if !s.isClient {
		s.recvLoop()
		return
	}

	settings := util.StringMap{
		"v":           "2",
		"client":      util.Verison,
		"padding-md5": s.padding.Load().Md5,
		"rs":          "1",
	}
	if s.migActive {
		// Advertise rail-switch support; the server only drives migration when
		// it both sees this flag and is itself enabled.
		settings["mig"] = "1"
	}
	f := newFrame(cmdSettings, 0)
	f.data = settings.ToBytes()
	s.buffering = true
	s.writeControlFrame(f)

	go s.recvLoop()
	go s.heartbeatLoop()
}

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
		// Best-effort H2 GOAWAY before closing, emitted only if connLock is
		// immediately available. The GOAWAY waste frame is pure camouflage
		// (skipping it has no functional effect), so Close must never block
		// waiting on a write stuck on the no-deadline data path — the same
		// TryLock discipline writeWindowUpdateWaste already uses. If the lock
		// is held, close the conn directly: the SetWriteDeadline above has
		// already unblocked any in-flight write, and net.Conn.Close is safe
		// to call concurrently with a Write in progress.
		if s.connLock.TryLock() {
			// Simulate H2 GOAWAY: emit a 17-byte waste frame before closing.
			// H2 GOAWAY = 9B H2 header + 4B last-stream-id + 4B error-code = 17B.
			// anytls: 7B header + 10B payload = 17B total, matching wire size.
			// Best-effort; errors ignored since we're closing.
			writeFrameBytes(s.conn, cmdWaste, 0, 10)
			err := s.conn.Close()
			s.connLock.Unlock()
			return err
		}
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
	defer s.Close()

	var receivedSettingsFromClient bool
	var hdr rawHeader

	for {
		if s.IsClosed() {
			return io.ErrClosedPipe
		}
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
					// Track received DATA bytes for WINDOW_UPDATE injection.
					// recvBytes and wndUpdateTrigger are only accessed here
					// (recvLoop goroutine), so no lock is needed.
					if s.wndUpdateTrigger > 0 {
						s.recvBytes += int(hdr.Length())
						if s.recvBytes >= s.wndUpdateTrigger {
							// Reset to 0 rather than subtracting the trigger:
							// the threshold is re-jittered below, so carrying
							// a remainder across intervals would bias the
							// spacing back toward a fixed average.
							s.recvBytes = 0
							s.writeWindowUpdateWaste()
							s.wndUpdateTrigger = nextWndInterval(s.wndUpdateBase)
						}
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

						if m["rs"] != "1" {
							f := newFrame(cmdAlert, 0)
							f.data = []byte("client does not support record shaper, please upgrade")
							s.writeControlFrame(f)
							buf.Put(buffer)
							return nil
						}

						// Activate the rail-switch for this session only when both
						// peers support it: the client advertised "mig" and this
						// server has migration enabled (signalled by a non-nil
						// registry). Set before any cmdSYN (which follows
						// cmdSettings on the wire), so server streams see it at birth.
						if s.migRegistry != nil && m["mig"] == "1" {
							s.migActive = true
						}

						paddingF := s.padding.Load()
						needUpdate := m["padding-md5"] != paddingF.Md5
						needServerSettings := false
						if v, err := strconv.Atoi(m["v"]); err == nil && v >= 2 {
							s.peerVersion.Store(uint32(v))
							needServerSettings = true
						}

						// Send cmdServerSettings first — this maps to the
						// H2 SETTINGS frame that a real Caddy server sends
						// immediately after the client preface.  The frame
						// is small (10 B) so padControlFrame shapes it to
						// an H2-characteristic size (14/17/45/22-30 B).
						if needServerSettings {
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

						// Simulate server SETTINGS_ACK: a real Caddy sends
						// SETTINGS_ACK after receiving the client preface.
						// Padded to 14-45B by padControlFrame (same limitation
						// as the client-side SETTINGS_ACK).
						if _, err = s.writeControlFrame(newFrame(cmdWaste, 0)); err != nil {
							buf.Put(buffer)
							return err
						}

						// Send cmdUpdatePaddingScheme separately — maps
						// loosely to H2 SETTINGS with extension params.
						// This only fires on first connect when the client
						// has a stale padding scheme.
						if needUpdate {
							f := newFrame(cmdUpdatePaddingScheme, 0)
							f.data = paddingF.RawScheme
							_, err = s.writeControlFrame(f)
							if err != nil {
								buf.Put(buffer)
								return err
							}
						}

						s.signalIdleReady()
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
							// A pushed scheme may turn idle injection on. idleReady is
							// already closed here (cmdServerSettings precedes this frame),
							// so a newly started loop runs at once.
							s.maybeStartIdleLoop()
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
						m := util.StringMapFromBytes(buffer)
						if v, err := strconv.Atoi(m["v"]); err == nil {
							s.peerVersion.Store(uint32(v))
						}
						// Simulate client SETTINGS_ACK: a real Go H2 client
						// sends a SETTINGS_ACK (9B) after receiving the server's
						// SETTINGS.  We emit a cmdWaste frame via writeControlFrame;
						// padControlFrame shapes it to an H2-characteristic control
						// frame size (14/17/22-30/45B).  The exact 9B is not
						// achievable through padControlFrame (appendWasteFrame adds
						// a minimum 7B header), but TLS record overhead (22B for
						// TLS 1.3) dilutes the difference.
						s.writeControlFrame(newFrame(cmdWaste, 0))
						s.signalIdleReady()
					}
					buf.Put(buffer)
				}
			case cmdMigrateReady:
				// Server -> client: the inner TLS handshake is complete; open a
				// dedicated carrier B and present this token (16-byte payload).
				// Payload is always drained so the stream stays in sync.
				if hdr.Length() > 0 {
					buffer := buf.Get(int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, buffer); err != nil {
						buf.Put(buffer)
						return err
					}
					if s.isClient && hdr.Length() >= migTokenLen {
						var tok migToken
						copy(tok[:], buffer[:migTokenLen])
						s.streamLock.RLock()
						stream, ok := s.streams[sid]
						s.streamLock.RUnlock()
						if ok && stream.mig != nil {
							go stream.mig.clientStartCarrier(tok)
						}
					}
					buf.Put(buffer)
				}
			case cmdMigrateGo:
				// Server -> client downlink barrier (ordering: see carrierToPipe).
				// Carries no payload; drain any unexpected bytes and tolerate a
				// wrong-direction frame so a malformed frame can never desync the mux.
				if hdr.Length() > 0 {
					buffer := buf.Get(int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, buffer); err != nil {
						buf.Put(buffer)
						return err
					}
					buf.Put(buffer)
				}
				if s.isClient {
					s.streamLock.RLock()
					stream, ok := s.streams[sid]
					s.streamLock.RUnlock()
					if ok && stream.mig != nil {
						stream.mig.clientOnMigrateGo()
					}
				}
			case cmdUplinkFin:
				// Client -> server uplink barrier (ordering: see carrierToPipe).
				// Carries no payload; drain any unexpected bytes and tolerate a
				// wrong-direction frame so a malformed frame can never desync the mux.
				if hdr.Length() > 0 {
					buffer := buf.Get(int(hdr.Length()))
					if _, err := io.ReadFull(s.conn, buffer); err != nil {
						buf.Put(buffer)
						return err
					}
					buf.Put(buffer)
				}
				if !s.isClient {
					s.streamLock.RLock()
					stream, ok := s.streams[sid]
					s.streamLock.RUnlock()
					if ok && stream.mig != nil {
						stream.mig.serverOnUplinkFin()
					}
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
	totalLen := len(data)
	written := 0

	for len(data) > 0 {
		chunk := data
		if len(chunk) > h2MaxFramePayload {
			chunk = chunk[:h2MaxFramePayload]
		}
		chunkLen := len(chunk)

		buffer := buf.NewSize(chunkLen + headerOverHeadSize)
		buffer.WriteByte(cmdPSH)
		binary.BigEndian.PutUint32(buffer.Extend(4), sid)
		binary.BigEndian.PutUint16(buffer.Extend(2), uint16(chunkLen))
		buffer.Write(chunk)

		// Data-frame writes have NO deadline, matching upstream.
		// On error mark connBroken so the session won't be reused,
		// but do NOT Close — let the recvLoop continue draining any
		// in-flight responses for other streams (upstream behaviour).
		_, err := s.writeConn(buffer.Bytes(), false)
		buffer.Release()
		if err != nil {
			s.connBroken.Store(true)
			// Return the payload bytes already flushed, per the
			// io.Writer contract (n < len(p) with a non-nil error),
			// so callers' byte accounting and io.Copy totals stay correct.
			return written, err
		}

		written += chunkLen
		data = data[chunkLen:]
	}

	return totalLen, nil
}

const (
	// earlyDataFrames is how many leading data frames of each stream are
	// eligible for split shaping.  The inner TLS handshake (ClientHello,
	// ChangeCipherSpec/Finished) lives in the first few frames.
	earlyDataFrames = 4
	// earlySplitThresh: frames at or below this size are sent as-is.  The
	// target-address frame and tiny handshake records carry no
	// distinctive single-record signature, so splitting them only adds
	// overhead.
	earlySplitThresh = 256
	// earlySplitMin is the minimum size of each piece produced by a split,
	// so the resulting records stay plausibly H2-DATA-sized.
	earlySplitMin = 48
)

// maxPaddingSchemeLen bounds an incoming cmdUpdatePaddingScheme payload.
// The frame length field is uint16 (so <=64 KB already), but a server the
// client trusts could still push a needlessly large scheme; 16 KB is far
// above any legitimate scheme (the built-in default is ~120 B).
const maxPaddingSchemeLen = 16 * 1024

// writeDataFrameShaped routes an early, mid-sized data frame through the
// splitter and everything else through the normal (16 KB-chunking) path.
//
// The split path is deliberately confined to the (earlySplitThresh,
// h2MaxFramePayload] range:
//   - At or below earlySplitThresh there is nothing worth splitting.
//   - Above h2MaxFramePayload, writeDataFrame already chunks the payload
//     into multiple <=16 KB records, so the "single large record"
//     signature is absent and there is nothing to split.  Routing large
//     frames here also keeps every cmdPSH chunk well under 65535 bytes,
//     avoiding the uint16 length-field overflow (and the consequent
//     receiver desync) that splitting an oversized chunk would cause, and
//     preserves the 16 KB-per-record H2 mimicry maintained everywhere else.
func (s *Session) writeDataFrameShaped(sid uint32, data []byte, early bool) (int, error) {
	if !early || len(data) <= earlySplitThresh || len(data) > h2MaxFramePayload {
		return s.writeDataFrame(sid, data)
	}
	return s.writeDataFrameSplit(sid, data)
}

// writeDataFrameSplit splits data into 2-3 random-sized cmdPSH frames and
// writes them back-to-back with no buffering and no delay.  The split is
// transparent to the inner TLS stream (the peer reassembles the byte
// stream) and uses the no-deadline data path so weak links are not killed.
//
// Precondition (guaranteed by writeDataFrameShaped): earlySplitThresh <
// len(data) <= h2MaxFramePayload, so every chunk is < 16384 < 65535 and the
// uint16 length field never overflows.
func (s *Session) writeDataFrameSplit(sid uint32, data []byte) (int, error) {
	total := len(data)
	parts := 2
	if total > 600 {
		parts = 3
	}
	offset := 0
	written := 0
	for i := 0; i < parts; i++ {
		var chunk []byte
		if i == parts-1 {
			chunk = data[offset:]
		} else {
			remaining := total - offset
			partsLeft := parts - i
			// Reserve at least earlySplitMin for each remaining piece.
			maxCut := remaining - earlySplitMin*(partsLeft-1)
			if maxCut <= earlySplitMin {
				chunk = data[offset:]
				if err := s.sendPSH(sid, chunk); err != nil {
					return written, err
				}
				return total, nil
			}
			cut := earlySplitMin + util.FastIntn(maxCut-earlySplitMin+1)
			chunk = data[offset : offset+cut]
			offset += cut
		}
		if err := s.sendPSH(sid, chunk); err != nil {
			// Return the payload bytes already flushed by earlier
			// sendPSH calls, per the io.Writer contract.
			return written, err
		}
		written += len(chunk)
	}
	return total, nil
}

// sendPSH builds and writes a single cmdPSH frame on the no-deadline data
// path.  On error it marks connBroken (matching writeDataFrame) without
// calling Close, so recvLoop keeps draining in-flight responses for other
// streams.  Callers must keep len(chunk) <= maxFrameDataLen (enforced by
// writeDataFrameShaped's h2MaxFramePayload bound).
func (s *Session) sendPSH(sid uint32, chunk []byte) error {
	buffer := buf.NewSize(len(chunk) + headerOverHeadSize)
	buffer.WriteByte(cmdPSH)
	binary.BigEndian.PutUint32(buffer.Extend(4), sid)
	binary.BigEndian.PutUint16(buffer.Extend(2), uint16(len(chunk)))
	buffer.Write(chunk)
	_, err := s.writeConn(buffer.Bytes(), false)
	buffer.Release()
	if err != nil {
		s.connBroken.Store(true)
	}
	return err
}

func (s *Session) writeControlFrame(frame frame) (int, error) {
	dataLen := len(frame.data)
	if dataLen > maxFrameDataLen {
		return 0, fmt.Errorf("control frame data too large: %d > %d", dataLen, maxFrameDataLen)
	}

	// Reserve the controlFramePadHint spare only while the frame is small
	// enough that the shaper could still pad it (WriteControl pads only while
	// len < maxTarget; WriteInitialFlush only up to HeadersTarget.Max — both
	// below controlFramePadHint under the default scheme). A frame already at
	// or above the hint is never padded, so the spare would be dead capacity;
	// appendWasteFrame still falls back to a fresh allocation for any custom
	// scheme whose target exceeds the hint, so the wire output is unchanged.
	padHint := controlFramePadHint
	if dataLen+headerOverHeadSize >= controlFramePadHint {
		padHint = 0
	}
	buffer := buf.NewSize(dataLen + headerOverHeadSize + padHint)
	buffer.WriteByte(frame.cmd)
	binary.BigEndian.PutUint32(buffer.Extend(4), frame.sid)
	binary.BigEndian.PutUint16(buffer.Extend(2), uint16(dataLen))
	buffer.Write(frame.data)

	// Control-frame writes use a 5 s deadline (via WriteControl)
	// and Close the session on failure, matching upstream.
	_, err := s.writeConn(buffer.Bytes(), true)
	buffer.Release()
	if err != nil {
		s.Close()
		return 0, err
	}

	return dataLen, nil
}

// writeConn handles buffer management.  When isCtrl is true the final
// write uses shaper.WriteControl (5 s deadline + padding); when false
// it uses shaper.WriteData (no deadline, no padding).
//
// A buffer flush uses WriteInitialFlush which pads the combined blob
// (cmdSettings + cmdSYN + cmdPSH) to an H2 HEADERS-like target size,
// reproducing the TLS record pattern of a Go stdlib H2 client.
func (s *Session) writeConn(b []byte, isCtrl bool) (n int, err error) {
	s.connLock.Lock()
	defer s.connLock.Unlock()

	if s.IsClosed() {
		return 0, io.ErrClosedPipe
	}

	if s.buffering {
		s.buffer = append(s.buffer, b...)
		return len(b), nil
	}
	if len(s.buffer) > 0 {
		// Flush: prepend buffer contents.  Shape the combined blob to
		// look like an H2 HEADERS frame — the first client-to-server
		// TLS record after the connection preface in a real Go H2 session.
		b = append(s.buffer, b...)
		s.buffer = nil
		return s.shaper.WriteInitialFlush(b)
	}

	// On a reused (pooled) session the SYN that opens a new stream is a
	// fresh request, which in a real Go H2 client is a HEADERS frame
	// (90-140 B), not a 14-45 B control frame.  Route the standalone SYN
	// through WriteInitialFlush so it is shaped to headers_target with a
	// 5 s deadline, matching the first stream's SYN.  The first stream's SYN
	// is buffered (s.buffering) and flushed via the branch above, so it never
	// reaches here; the two paths therefore agree.
	if isCtrl && len(b) > 0 && b[0] == cmdSYN {
		return s.shaper.WriteInitialFlush(b)
	}

	if isCtrl {
		return s.shaper.WriteControl(b)
	}
	return s.shaper.WriteData(b)
}

// maybeStartIdleLoop spawns idleLoop once, iff idle injection is enabled by
// the current padding scheme. The decision reads the live padding factory
// (an atomic load of an immutable value) rather than the shaper's lazily
// refreshed cache, so it is correct immediately after a server-pushed scheme
// is applied and needs no connLock — keeping it safe to call from recvLoop
// without ever blocking the read path. idleLoopOnce makes repeated calls
// (Run + each scheme update) a no-op once started.
func (s *Session) maybeStartIdleLoop() {
	cfg := s.padding.Load().RecordConfig
	if len(cfg.IdleSizes) == 0 || cfg.IdleIntervalMs[1] <= 0 {
		return
	}
	s.idleLoopOnce.Do(func() { go s.idleLoop() })
}

func (s *Session) idleLoop() {
	select {
	case <-s.die:
		return
	case <-s.idleReady:
	}

	s.connLock.Lock()
	// Sync the shaper's cached config to the current (possibly just-pushed)
	// scheme before deciding whether to run; otherwise the stale default
	// (idle off) would make this loop exit immediately even though a pushed
	// scheme enabled injection. Subsequent IdleInterval/BuildIdleFrame reads
	// then see the fresh config (BuildIdleFrame also refreshes on its own).
	s.shaper.maybeRefreshConfig()
	enabled := s.shaper.IdleEnabled()
	s.connLock.Unlock()
	if !enabled {
		return
	}

	for {
		s.connLock.Lock()
		interval := s.shaper.IdleInterval()
		s.connLock.Unlock()

		select {
		case <-s.die:
			return
		case <-time.After(interval):
			select {
			case <-s.die:
				return
			default:
			}

			s.connLock.Lock()
			if s.IsClosed() || s.connBroken.Load() {
				s.connLock.Unlock()
				if s.connBroken.Load() && !s.IsClosed() {
					s.Close()
				}
				return
			}
			if s.buffering {
				s.connLock.Unlock()
				continue
			}
			frame := s.shaper.BuildIdleFrame()
			if frame == nil {
				s.connLock.Unlock()
				continue
			}
			s.conn.SetWriteDeadline(time.Now().Add(writeDeadline))
			_, err := s.conn.Write(frame)
			s.conn.SetWriteDeadline(time.Time{})
			if err == nil {
				s.shaper.LastWrite = time.Now()
			}
			s.connLock.Unlock()

			if err != nil {
				s.connBroken.Store(true)
				s.Close()
				return
			}
		}
	}
}

// nextWndInterval returns base +/- 25 % jitter, modelling the non-rigid
// point at which Go's H2 flow controller emits a WINDOW_UPDATE rather than
// a fixed byte count (the fixed interval was a deterministic tool signature).
func nextWndInterval(base int) int {
	if base <= 0 {
		return 0
	}
	jitter := base / 4
	return base - jitter + util.FastIntn(2*jitter+1)
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

// writeWindowUpdateWaste emits a 26-byte cmdWaste record modelling the
// stream-level + connection-level WINDOW_UPDATE pair that a real Go H2
// client writes back-to-back (two 13 B frames = 7 B anytls header + 6 B
// payload each, the wire size of an H2 WINDOW_UPDATE).
//
// It is called from recvLoop.  anytls has no real flow control, so this is
// a pure mimicry frame: skipping it has zero functional effect.  It
// therefore uses TryLock and bails if the connLock is held -- a data write
// is in progress on the no-deadline path, and blocking here would stall
// recvLoop (and thus all reads).  Skipping the cosmetic frame is strictly
// safer than blocking, at the cost of slightly weaker H2 mimicry during
// simultaneous heavy upload + download.
func (s *Session) writeWindowUpdateWaste() {
	if s.IsClosed() || s.connBroken.Load() {
		return
	}
	if !s.connLock.TryLock() {
		return
	}
	defer s.connLock.Unlock()
	if s.IsClosed() || s.connBroken.Load() {
		return
	}

	var frame [26]byte
	frame[0] = cmdWaste
	binary.BigEndian.PutUint16(frame[5:7], 6)
	util.FillRandom(frame[7:13])
	frame[13] = cmdWaste
	binary.BigEndian.PutUint16(frame[18:20], 6)
	util.FillRandom(frame[20:26])

	// This is a purely cosmetic camouflage frame, so the write is
	// best-effort: use a SHORT (1 s) deadline and on a clean failure
	// (nothing written, e.g. a transiently full uplink) simply return
	// without storing connBroken or tearing the session down — that would
	// otherwise (a) stall recvLoop for the full deadline and (b) falsely
	// mark the session broken; a genuinely dead conn is still detected by
	// the read path.  A PARTIAL write (n > 0) does corrupt frame framing,
	// so in that case the session must be torn down.  The deadline is
	// always reset so it never leaks onto a later non-cosmetic write.
	s.conn.SetWriteDeadline(time.Now().Add(time.Second))
	n, err := s.conn.Write(frame[:])
	s.conn.SetWriteDeadline(time.Time{})
	if err != nil {
		if n > 0 {
			s.connBroken.Store(true)
		}
		return
	}
	s.shaper.LastWrite = time.Now()
}

// writeFrameBytes writes a single anytls frame directly to the conn.
// Used only in Close() for the GOAWAY simulation where we need a raw
// write without shaping.  The caller must hold connLock.
func writeFrameBytes(conn net.Conn, cmd byte, sid uint32, randomPayloadLen int) {
	b := make([]byte, headerOverHeadSize+randomPayloadLen)
	b[0] = cmd
	binary.BigEndian.PutUint32(b[1:5], sid)
	binary.BigEndian.PutUint16(b[5:7], uint16(randomPayloadLen))
	if randomPayloadLen > 0 {
		util.FillRandom(b[headerOverHeadSize:])
	}
	conn.SetWriteDeadline(time.Now().Add(time.Second))
	conn.Write(b) // best-effort, error ignored
	conn.SetWriteDeadline(time.Time{})
}
