package session

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/anytls/sing-anytls/util"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

// ---------------------------------------------------------------------------
// 0-RTT rail-switch ("换轨") — bidirectional stream migration.
//
// Keep gRPC-class 0-RTT and the existing TLS-in-TLS-resistant, traffic-shaped
// mux for every flow's start (and, for a TLS flow, its whole inner handshake),
// then move the steady-state BULK of a long flow — both directions — onto a
// dedicated raw connection ("carrier B"), so it no longer suffers the mux's
// single-TCP head-of-line blocking. After the cut-over the flow is a standalone
// TCP connection with its own congestion window, and B carries only
// post-handshake bytes, so a nested TLS handshake never appears on it — the
// anti-analysis contract.
//
// Everything is fail-safe: a dial failure, an unknown/expired token, a closed
// stream, or any unrecognised flow simply leaves the traffic on the mux — the
// original, always-correct path. Enabled per outbound/inbound (EnableMigration,
// ORed with the ANYTLS_MIGRATION env default) and negotiated via a settings
// flag; when off, the wire output and code paths are byte-for-byte unchanged.
// ---------------------------------------------------------------------------

// migrationEnvDefault is the package-level default, read once at load from the
// ANYTLS_MIGRATION env var. The per-outbound / per-inbound config option ORs
// with it (anytls.ClientConfig/ServiceConfig.EnableMigration), so migration can
// be enabled by config, by env, or both. When neither is set the default build
// behaves identically to upstream.
var migrationEnvDefault = os.Getenv("ANYTLS_MIGRATION") == "1"

// MigrationEnvDefault reports the ANYTLS_MIGRATION env default.
func MigrationEnvDefault() bool { return migrationEnvDefault }

const (
	migTokenLen           = 16
	migCarrierDialTimeout = 10 * time.Second
	// migRegistryTTL bounds how long a server holds a pending token before
	// giving up on the carrier (the client's B may have been blocked); the
	// flow then just stays on the mux.
	migRegistryTTL = 15 * time.Second

	// Carrier B opens with the normal password+padding prefix (from dialOut)
	// followed by one cmdMigrateCarrier frame. Pad that frame's payload (token
	// + random filler) to a plausible request size so B's first client->server
	// record resembles the small request that precedes a normal HTTPS
	// download, instead of a tiny 23-byte tell. The server reads the declared
	// length and uses only the leading token.
	migCarrierPadMin   = 128
	migCarrierPadRange = 512
	migCarrierMaxData  = 4096 // server-side sanity cap on the carrier payload

	// migCarrierGraceTimeout bounds how long carrier B is kept open after the
	// stream ends while waiting for the peer's half-close, so a peer that never
	// closes cannot leak the connection. The normal graceful four-way FIN close
	// completes in well under a round-trip; this watchdog only fires for a stuck
	// peer (see closeOnStreamEnd).
	migCarrierGraceTimeout = 30 * time.Second
)

type migToken [migTokenLen]byte

// MigRegistry maps a pending migration token to the server stream awaiting its
// dedicated carrier B. It lives on the Service because B arrives as a fresh
// connection, demultiplexed from the originating mux session.
type MigRegistry struct {
	mu      sync.Mutex
	pending map[migToken]*streamMig
}

func NewMigRegistry() *MigRegistry {
	return &MigRegistry{pending: make(map[migToken]*streamMig)}
}

func (r *MigRegistry) register(tok migToken, sm *streamMig) {
	r.mu.Lock()
	r.pending[tok] = sm
	r.mu.Unlock()
	time.AfterFunc(migRegistryTTL, func() {
		r.mu.Lock()
		if r.pending[tok] == sm {
			delete(r.pending, tok)
		}
		r.mu.Unlock()
	})
}

func (r *MigRegistry) take(tok migToken) *streamMig {
	r.mu.Lock()
	sm := r.pending[tok]
	delete(r.pending, tok)
	r.mu.Unlock()
	return sm
}

// streamMig holds per-stream rail-switch state. It is attached to a Stream
// (client and server) only while migration is negotiated active on the
// session, so a nil s.mig means "behave exactly like upstream".
type streamMig struct {
	stream *Stream
	sess   *Session

	// server only: drives the cut-over decision from the relayed inner records.
	detector *handshakeDetector

	// writeMu serialises this side's Stream.Write against the cut-over, so the
	// migration barrier (cmdMigrateGo for downlink, cmdUplinkFin for uplink) is
	// emitted exactly between the last mux frame and the first B frame for this
	// stream.
	writeMu sync.Mutex
	// bWriteConn, once non-nil, diverts this side's writes straight onto B (raw,
	// unframed): server downlink, client uplink. Guarded by writeMu.
	bWriteConn net.Conn

	bConn     net.Conn      // the dedicated carrier, for close coordination
	doneCh    chan struct{} // closed when the carrier is released (stream death)
	closeOnce sync.Once

	triggered      atomic.Bool // server: cmdMigrateReady already sent
	tapsDone       atomic.Bool // server: detector reached a final verdict; stop tapping
	payloadStarted atomic.Bool // server: anytls header consumed, taps may observe payload
	bReady         atomic.Bool // carrier B established (both sides)
	goSeen         atomic.Bool // client: cmdMigrateGo received
	cutoverOnce    sync.Once   // client: downlink feeder + uplink seam committed once
	uplinkFinOnce  sync.Once   // server: uplink feeder started once

	// Graceful carrier teardown (avoids RST-discarding in-flight bulk). Carrier
	// B is full-duplex after the cut-over, so each half is closed independently:
	// the write half via a TCP/TLS half-close (FIN/close_notify, flushing every
	// buffered byte) when this side's source EOFs, and the read half when the
	// peer's half-close yields a clean io.EOF. Only once BOTH halves are done is
	// the carrier fully Closed — by then both socket buffers are drained, so the
	// final Close is graceful (no RST) and the migrated byte stream is delivered
	// in full across the seam at end-of-stream, just as at the start.
	bWriteHalfClosed atomic.Bool // this side half-closed B's write direction
	bReadHalfClosed  atomic.Bool // carrierToPipe saw a clean EOF on B's read direction
}

func newStreamMig(s *Stream, sess *Session) *streamMig {
	sm := &streamMig{stream: s, sess: sess, doneCh: make(chan struct{})}
	if !sess.isClient {
		sm.detector = newHandshakeDetector(sess.migMinBulk)
		sm.detector.tlsOnly = sess.migTLSOnly
	}
	return sm
}

// observeServerRead feeds relayed uplink (client->server) PAYLOAD bytes to the
// detector. Called from the server Stream.Read tap. It is inert until
// payloadStarted (so the anytls destination header is not mistaken for inner
// records), and once a final verdict is in (migrated or non-migratable)
// tapsDone makes it a single atomic load. An opaque/bulk flow can become ready
// on uplink alone, so the cut-over offer is checked from here too.
func (sm *streamMig) observeServerRead(p []byte) {
	if sm.detector == nil || sm.tapsDone.Load() || !sm.payloadStarted.Load() {
		return
	}
	sm.detector.observeUplink(p)
	if sm.detector.Aborted() {
		sm.tapsDone.Store(true)
		return
	}
	sm.serverMaybeTrigger()
}

// observeServerWrite is the downlink counterpart of observeServerRead, fed from
// the server Stream.Write tap while it still writes the mux.
func (sm *streamMig) observeServerWrite(p []byte) {
	if sm.detector == nil || sm.tapsDone.Load() || !sm.payloadStarted.Load() {
		return
	}
	sm.detector.observeDownlink(p)
	if sm.detector.Aborted() {
		sm.tapsDone.Store(true)
	}
}

// serverMaybeTrigger fires the cut-over offer once the detector authorises it.
// Single-shot via triggered. Called from the server Stream.Write tap.
func (sm *streamMig) serverMaybeTrigger() {
	if sm.detector == nil || sm.tapsDone.Load() {
		return
	}
	if !sm.detector.Ready() {
		return
	}
	if !sm.triggered.CompareAndSwap(false, true) {
		return
	}
	// Verdict reached: stop tapping on both directions from here on.
	sm.tapsDone.Store(true)
	var tok migToken
	if _, err := rand.Read(tok[:]); err != nil {
		return // fail-safe: no migration, stay on mux
	}
	if sm.sess.migRegistry != nil {
		sm.sess.migRegistry.register(tok, sm)
	}
	f := newFrame(cmdMigrateReady, sm.stream.id)
	f.data = append([]byte(nil), tok[:]...)
	// Best-effort: a write failure just means no migration; the mux path
	// (which this same Write is about to take) remains fully correct.
	sm.sess.writeControlFrame(f)
}

// clientStartCarrier runs on the client when cmdMigrateReady arrives: it dials
// the dedicated carrier B, presents the token, and parks B until cmdMigrateGo.
func (sm *streamMig) clientStartCarrier(tok migToken) {
	if sm.sess.client == nil {
		return
	}
	ctx, cancel := context.WithTimeout(sm.sess.client.die, migCarrierDialTimeout)
	defer cancel()

	conn, err := sm.sess.client.dialOut(ctx)
	if err != nil {
		return // fail-safe: stay on mux
	}

	// Pad the carrier frame so B's first client->server record is request-sized
	// (token + random filler), masking the bare 23-byte cmdMigrateCarrier tell.
	padLen := migCarrierPadMin + util.FastIntn(migCarrierPadRange)
	dataLen := migTokenLen + padLen
	hdr := make([]byte, headerOverHeadSize+dataLen)
	hdr[0] = cmdMigrateCarrier
	binary.BigEndian.PutUint32(hdr[1:5], sm.stream.id)
	binary.BigEndian.PutUint16(hdr[5:7], uint16(dataLen))
	copy(hdr[headerOverHeadSize:], tok[:])
	util.FillRandom(hdr[headerOverHeadSize+migTokenLen:])

	// Publish bConn under writeMu before the single carrier-frame write, so the
	// cut-over and close paths read a consistently-synchronised value.
	sm.writeMu.Lock()
	sm.bConn = conn
	sm.writeMu.Unlock()
	if _, err := conn.Write(hdr); err != nil {
		sm.closeCarrier()
		return
	}
	sm.bReady.Store(true)
	sm.maybeClientCutover()
}

func (sm *streamMig) clientOnMigrateGo() {
	sm.goSeen.Store(true)
	sm.maybeClientCutover()
}

// maybeClientCutover commits the client's half of the cut-over once BOTH the
// carrier is up and the downlink barrier has been seen (either arrival order),
// exactly once: it switches client uplink onto B behind the cmdUplinkFin
// barrier and starts pumping downlink off B into the stream pipe.
func (sm *streamMig) maybeClientCutover() {
	if !sm.bReady.Load() || !sm.goSeen.Load() {
		return
	}
	sm.cutoverOnce.Do(func() {
		// Uplink seam: under writeMu (see the writeMu field) emit cmdUplinkFin
		// then divert client writes onto B.
		sm.writeMu.Lock()
		bc := sm.bConn
		if sm.stream.dieErr.Load() == nil {
			sm.sess.writeControlFrame(newFrame(cmdUplinkFin, sm.stream.id))
			sm.bWriteConn = bc
		}
		sm.writeMu.Unlock()
		// Downlink: pump B into the stream pipe (the read side is oblivious).
		go sm.carrierToPipe(bc)
	})
}

// carrierToPipe pumps post-barrier data off carrier B into the stream's
// existing pipe, so Stream.Read never notices the carrier swap — client
// downlink and server uplink share this exact mirror-image path. Ordering is
// guaranteed by the barrier: recvLoop delivered every pre-barrier mux frame
// into pipeW before processing the barrier (cmdMigrateGo / cmdUplinkFin), and
// only then was this allowed to start, so the bytes append with no gap,
// overlap or reorder.
func (sm *streamMig) carrierToPipe(bc net.Conn) {
	var readErr error
	b := make([]byte, 32*1024)
	for {
		n, err := bc.Read(b)
		if n > 0 {
			if _, werr := sm.stream.pipeW.Write(b[:n]); werr != nil {
				readErr = werr
				break
			}
		}
		if err != nil {
			readErr = err
			break
		}
	}
	if readErr == io.EOF {
		// Clean end of the carried direction: the peer half-closed B (FIN /
		// close_notify), so every byte it sent has now been read and, via the
		// synchronous pipe, already consumed by this side's Stream.Read. Signal
		// EOF on the read side only (Stream.Read -> io.EOF), leaving the write
		// half live, and retire the read half. The stream is NOT torn down here,
		// so the opposite direction keeps flowing until it too half-closes.
		sm.bReadHalfClosed.Store(true)
		sm.stream.pipeW.Close()
		sm.maybeFullCloseCarrier()
		return
	}
	// Hard error (B reset, read/write failure): B is already broken, so close it
	// at once (no graceful FIN to preserve) and fall back to the abrupt teardown
	// — also sends cmdFIN on the mux, closing the lifecycle anchor.
	sm.closeCarrier()
	sm.stream.closeWithError(io.EOF)
}

// closeWrite half-closes carrier B's write direction for this side (server
// downlink, client uplink) when the local source EOFs, flushing every buffered
// byte and sending a clean FIN/close_notify so the peer's carrierToPipe reads
// the whole direction to a lossless io.EOF. It is the migrated equivalent of a
// TCP half-close and is what makes end-of-stream delivery exact. Returns nil so
// the sing-box relay keeps the read side open to drain the opposite direction.
func (sm *streamMig) closeWrite() error {
	sm.writeMu.Lock()
	bc := sm.bWriteConn
	sm.writeMu.Unlock()
	if bc == nil {
		// Not cut over (short flow still on the mux): anytls has no mux
		// half-close, so behave exactly like upstream's full close.
		return sm.stream.closeWithError(io.ErrClosedPipe)
	}
	if sm.bWriteHalfClosed.CompareAndSwap(false, true) {
		// N.CloseWrite unwraps any conn wrapper (e.g. the server's
		// bufio.CachedConn) down to the outer-TLS conn's CloseWrite.
		N.CloseWrite(bc)
		sm.maybeFullCloseCarrier()
	}
	return nil
}

// maybeFullCloseCarrier fully closes B once both halves are retired, so the
// final Close lands only after both socket buffers have drained (graceful FIN,
// never a data-discarding RST). Idempotent via closeCarrier's closeOnce.
func (sm *streamMig) maybeFullCloseCarrier() {
	if sm.bWriteHalfClosed.Load() && sm.bReadHalfClosed.Load() {
		sm.closeCarrier()
	}
}

// serverAttachCarrier wires an accepted carrier B to its server stream: it
// emits the downlink barrier on the mux and then diverts downlink onto B.
func (sm *streamMig) serverAttachCarrier(conn net.Conn) {
	sm.writeMu.Lock()
	if sm.stream.dieErr.Load() != nil {
		// Stream already gone; nothing to migrate.
		sm.writeMu.Unlock()
		conn.Close()
		return
	}
	// cmdMigrateGo is the downlink barrier; emitting it under writeMu lands it
	// between the last mux downlink frame and the first byte written to B.
	sm.sess.writeControlFrame(newFrame(cmdMigrateGo, sm.stream.id))
	sm.bConn = conn
	sm.bReady.Store(true)
	sm.bWriteConn = conn
	sm.writeMu.Unlock()
}

// serverOnUplinkFin starts reading uplink off B (via carrierToPipe) when the
// uplink barrier arrives. At most once.
func (sm *streamMig) serverOnUplinkFin() {
	sm.uplinkFinOnce.Do(func() {
		sm.writeMu.Lock()
		bc := sm.bConn
		sm.writeMu.Unlock()
		if bc != nil {
			go sm.carrierToPipe(bc)
		}
	})
}

// closeCarrier closes B once, idempotently, and releases any goroutine parked
// in waitCarrier. Called from the stream's close path so the dedicated
// connection never leaks.
func (sm *streamMig) closeCarrier() {
	sm.closeOnce.Do(func() {
		sm.writeMu.Lock()
		bc := sm.bConn
		sm.writeMu.Unlock()
		if bc != nil {
			bc.Close()
		}
		close(sm.doneCh)
	})
}

// closeOnStreamEnd is invoked from the stream lifecycle teardown
// (closeWithError / closeLocally). With the flow cut over to carrier B it must
// NOT hard-close B here: the relay can end the downlink (origin EOF) and tear
// the stream down while the peer's own close_notify/FIN is still in flight, and
// a full Close at that instant races that trailing segment into a data-less RST
// (the kernel RSTs a just-released socket when the peer's bytes land late — seen
// at end-of-stream on a real link). Instead it half-closes our write (FIN) and
// leaves the read half to carrierToPipe, which retires it on the peer's clean
// EOF and only then runs the final Close — completing a graceful four-way FIN
// handshake. A watchdog force-closes after migCarrierGraceTimeout so a peer that
// never half-closes cannot leak the carrier. When the flow never cut over
// (bWriteConn nil) the pending/unused carrier is closed immediately, exactly as
// before, so the non-migration and dial-failure paths are unchanged.
func (sm *streamMig) closeOnStreamEnd() {
	sm.writeMu.Lock()
	bc := sm.bWriteConn
	sm.writeMu.Unlock()
	if bc == nil {
		sm.closeCarrier()
		return
	}
	if sm.bWriteHalfClosed.CompareAndSwap(false, true) {
		N.CloseWrite(bc)
	}
	// Closes now iff carrierToPipe has already retired the read half; otherwise
	// it stays open until that clean EOF arrives, with the watchdog as backstop.
	sm.maybeFullCloseCarrier()
	time.AfterFunc(migCarrierGraceTimeout, sm.closeCarrier)
}

// waitCarrier blocks until the carrier is released (the stream closed). The
// server's listener goroutine parks here so it keeps the carrier connection
// open for the stream's whole life, exactly as session.Run blocks for a normal
// session — otherwise the inbound would reclaim B the moment NewConnection
// returned.
func (sm *streamMig) waitCarrier() {
	<-sm.doneCh
}

// MaybeAcceptCarrier inspects a freshly-authenticated inbound connection: if
// its first frame is a cmdMigrateCarrier it is consumed as a dedicated carrier
// B (handled==true) and attached to its waiting stream; otherwise the frame
// header is rewound and the (wrapped) connection is returned for normal session
// handling. Only called on the server when migration is enabled.
func MaybeAcceptCarrier(conn net.Conn, reg *MigRegistry) (net.Conn, bool, error) {
	var hdr rawHeader
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return conn, false, err
	}
	if hdr.Cmd() != cmdMigrateCarrier {
		// Not a carrier: hand the header bytes back so the session reads its
		// real first frame (cmdSettings) intact.
		cached := bufio.NewCachedConn(conn, buf.As(append([]byte(nil), hdr[:]...)))
		return cached, false, nil
	}
	// The payload is token (16 B) + request-sized disguise padding; read it all
	// and keep only the leading token. Bounded by migCarrierMaxData.
	length := int(hdr.Length())
	if length < migTokenLen || length > migCarrierMaxData {
		conn.Close()
		return conn, true, nil
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		conn.Close()
		return conn, true, nil
	}
	var tok migToken
	copy(tok[:], payload[:migTokenLen])
	if reg == nil {
		conn.Close()
		return conn, true, nil
	}
	sm := reg.take(tok)
	if sm == nil {
		// Unknown or expired token: drop the carrier; the flow stays on the mux.
		conn.Close()
		return conn, true, nil
	}
	sm.serverAttachCarrier(conn)
	// Hold the carrier open for the stream's whole life (mirrors how the
	// normal path blocks inside session.Run), then let NewConnection return.
	sm.waitCarrier()
	return conn, true, nil
}
