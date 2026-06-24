package session

import "sync"

// ---------------------------------------------------------------------------
// Inner-TLS handshake detector (server side, 0-RTT rail-switch / "换轨").
//
// The security contract: carrier B must NEVER carry the inner TLS handshake — a
// censor watching B must see only post-handshake application_data records, so
// the tell-tale nested-handshake burst stays buried in the shaped mux. The
// server relays the inner stream in cleartext (it terminates the outer proxy
// TLS), so it reads the inner record headers directly and only reports the
// handshake complete once it demonstrably has, biased deliberately LATE:
// reporting too late costs a few more KB on the mux, reporting too early leaks
// handshake records onto B and breaks the contract — an asymmetric risk.
// ---------------------------------------------------------------------------

const (
	tlsRecordHandshake   = 0x16
	tlsRecordChangeMagic = 0x14 // ChangeCipherSpec
	tlsRecordAppData     = 0x17

	tlsHandshakeClientHello = 0x01
	tlsHandshakeServerHello = 0x02
)

// migMinBulkBytes is the DEFAULT post-handshake volume that must accumulate
// before a flow migrates — a single gate serving two purposes: (1) an
// anti-analysis margin far larger than any inner handshake plus its stragglers
// (a TLS 1.3 NewSessionTicket / KeyUpdate), so the whole nested handshake rides
// the shaped mux, never carrier B; and (2) a worth-migrating gate, so only a
// genuine bulk flow spawns a dedicated connection (bounding the connection
// cost). Overridable per-service (ServiceConfig.MigrationMinBulkBytes -> the
// `migration_min_bulk_bytes` inbound option); a var so tests can lower it.
var migMinBulkBytes = 64 * 1024

// migMinBulkFloor clamps an explicitly-configured gate so a foot-gun value
// (e.g. a few hundred bytes) cannot shrink the worth-migrating gate to near
// nothing. The handshake itself always rides the mux regardless (the gate only
// counts downlink AFTER the handshake completes), so this is a sanity floor,
// not a hard anti-analysis dependency. A configured 0 means "use the default".
const migMinBulkFloor = 2 * 1024

// resolveMinBulk turns a configured value into the effective gate: 0 -> default,
// otherwise clamped up to the floor.
func resolveMinBulk(n int) int {
	if n <= 0 {
		return migMinBulkBytes
	}
	if n < migMinBulkFloor {
		return migMinBulkFloor
	}
	return n
}

// recordScanner walks a one-directional TLS record byte stream and reports
// each completed record's outer type, length and first body byte (the
// handshake message type for a handshake record).  It tolerates records split
// across arbitrary feed() boundaries by buffering the 5-byte header and
// counting the body remainder; it never buffers a whole record.
type recordScanner struct {
	hdr       [5]byte
	hdrLen    int  // 0..5 header bytes buffered so far
	bodyLeft  int  // body bytes still to skip in the current record
	recLength int  // declared body length of the current record
	recType   byte // outer ContentType of the current record
	firstByte byte // first body byte of the current record
	gotFirst  bool // firstByte captured for the current record
	reported  bool // onRecord already fired for the current record
	broken    bool // a malformed length was seen; stop trusting this stream
}

// feed advances the scanner over p, invoking onRecord(type, length, firstByte)
// exactly once per record — as soon as the first body byte is known (or
// immediately for a zero-length record, with firstByte 0). Records may be
// split across any number of feed() calls; only the 5-byte header is buffered.
func (rs *recordScanner) feed(p []byte, onRecord func(recType byte, length int, firstByte byte)) {
	if rs.broken {
		return
	}
	for len(p) > 0 {
		if rs.hdrLen < 5 {
			n := copy(rs.hdr[rs.hdrLen:], p)
			rs.hdrLen += n
			p = p[n:]
			if rs.hdrLen < 5 {
				return
			}
			rs.recType = rs.hdr[0]
			rs.recLength = int(rs.hdr[3])<<8 | int(rs.hdr[4])
			// A TLS record body is at most 2^14 + 2048 (TLS 1.3 expansion).
			// Anything larger means this is not a TLS stream we understand.
			if rs.recLength > 0x4800 {
				rs.broken = true
				return
			}
			rs.bodyLeft = rs.recLength
			rs.gotFirst = false
			rs.reported = false
			rs.firstByte = 0
			if rs.recLength == 0 {
				onRecord(rs.recType, 0, 0)
				rs.reported = true
				rs.resetForNext()
				continue
			}
		}
		take := rs.bodyLeft
		if take > len(p) {
			take = len(p)
		}
		if !rs.gotFirst && take > 0 {
			rs.firstByte = p[0]
			rs.gotFirst = true
		}
		if !rs.reported && rs.gotFirst {
			onRecord(rs.recType, rs.recLength, rs.firstByte)
			rs.reported = true
		}
		rs.bodyLeft -= take
		p = p[take:]
		if rs.bodyLeft == 0 {
			rs.resetForNext()
		}
	}
}

func (rs *recordScanner) resetForNext() {
	rs.hdrLen = 0
}

type migDetectState int

const (
	migDetectInit          migDetectState = iota // waiting for the first uplink record
	migDetectClientHello                         // CH seen, waiting for ServerHello (TLS path)
	migDetectServerHello                         // SH seen, waiting for both flights (TLS path)
	migDetectHandshakeDone                       // handshake complete, waiting out the gate (TLS path)
	migDetectBulk                                // opaque / non-TLS flow (UoT-UDP, plaintext …): gate purely on volume
	migDetectReady                               // cut-over authorised
	migDetectAborted                             // ruled non-migratable: never migrate
)

// handshakeDetector tracks inner TLS handshake progress from the relayed
// records of both directions.  observeUplink is fed client->server bytes
// (where ClientHello and the client's Finished live) and observeDownlink is
// fed server->client bytes (ServerHello and the server flight).  The two
// observe methods run on different goroutines (the server's Stream.Read and
// Stream.Write), so all state is guarded by mu.
type handshakeDetector struct {
	mu       sync.Mutex
	state    migDetectState
	upScan   recordScanner
	downScan recordScanner

	serverHelloSeen   bool
	serverFlightAfter int  // downlink records completed after ServerHello
	clientFlightAfter bool // an uplink record started after ServerHello was seen
	downlinkSinceDone int  // (TLS) downlink bytes relayed after the handshake looked done
	bulkBytes         int  // (bulk) total bytes relayed in both directions
	minBulk           int  // effective bulk gate for this flow
	tlsOnly           bool // restrict migration to TLS flows (opaque flows abort)
}

func newHandshakeDetector(minBulk int) *handshakeDetector {
	return &handshakeDetector{state: migDetectInit, minBulk: resolveMinBulk(minBulk)}
}

func (d *handshakeDetector) Ready() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.state == migDetectReady
}

func (d *handshakeDetector) Aborted() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.state == migDetectAborted
}

func (d *handshakeDetector) abort() { d.state = migDetectAborted }

// observeUplink consumes client->server cleartext payload bytes (fed only
// after the anytls stream header has been consumed).
func (d *handshakeDetector) observeUplink(p []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch d.state {
	case migDetectAborted, migDetectHandshakeDone, migDetectReady:
		// TLS path past the handshake is driven by the downlink gate; aborted
		// and ready are terminal.
		return
	case migDetectBulk:
		d.addBulk(len(p))
		return
	}
	// Decide the mode from the first payload byte (robust against a non-TLS
	// payload whose bytes don't parse as a small record).
	if d.state == migDetectInit {
		if len(p) == 0 {
			return
		}
		if p[0] != tlsRecordHandshake {
			// Not a TLS handshake record: an opaque flow (UoT-UDP, plaintext,
			// custom protocols). In tls-only mode such flows are never migrated
			// (they stay on the shaped mux); otherwise they migrate on a pure
			// volume gate — the early bytes (incl. any non-TLS handshake such as
			// a QUIC Initial) still ride the mux until the gate is crossed.
			if d.tlsOnly {
				d.abort()
				return
			}
			d.state = migDetectBulk
			d.addBulk(len(p))
			return
		}
		// First byte 0x16 = a TLS handshake record (the client's ClientHello):
		// use the precise handshake gate. The scanner tracks the record stream
		// from here so the post-ServerHello client flight can be detected; a
		// downlink that is not a ServerHello later aborts (see observeDownlink).
		d.state = migDetectClientHello
	}
	// migDetectClientHello / migDetectServerHello: track uplink record boundaries.
	d.upScan.feed(p, func(recType byte, length int, firstByte byte) {
		if d.state == migDetectServerHello {
			// First uplink record begun after ServerHello = the client's
			// CCS/Finished flight. Record that the client has responded.
			d.clientFlightAfter = true
			d.maybeHandshakeDone()
		}
	})
}

// observeDownlink consumes server->client cleartext payload bytes.
func (d *handshakeDetector) observeDownlink(p []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch d.state {
	case migDetectAborted, migDetectReady:
		return
	case migDetectBulk:
		d.addBulk(len(p))
		return
	case migDetectHandshakeDone:
		d.downlinkSinceDone += len(p)
		if d.downlinkSinceDone >= d.minBulk {
			d.state = migDetectReady
		}
		return
	}
	// migDetectInit / migDetectClientHello / migDetectServerHello
	d.downScan.feed(p, func(recType byte, length int, firstByte byte) {
		switch d.state {
		case migDetectClientHello:
			// First downlink record after ClientHello must be ServerHello.
			if recType == tlsRecordHandshake && (firstByte == tlsHandshakeServerHello || length == 0) {
				d.state = migDetectServerHello
				d.serverHelloSeen = true
			} else {
				d.abort()
			}
		case migDetectServerHello:
			// Read the negotiated version off the server's post-ServerHello
			// flight: TLS 1.3 sends it as encrypted application_data (0x17, after
			// a 0x14 ChangeCipherSpec), whereas TLS 1.2 keeps emitting
			// cleartext-TYPED handshake records (0x16: Certificate / SKE / … in a
			// full handshake, or the Finished in a resumption). A second 0x16
			// from the server therefore means TLS 1.2 — the ONLY version with
			// renegotiation, whose mid-stream handshake burst would otherwise
			// leak onto carrier B after the cut-over (no nested handshake may
			// ride B; that is the anti-analysis contract). Refuse to migrate it:
			// the flow stays on the shaped mux, where a later renegotiation is
			// shaped like everything else. Ambiguous 1.3 cases (e.g. a
			// HelloRetryRequest, also a server 0x16) fail safe here too — a
			// missed optimisation, never a leak.
			if recType == tlsRecordHandshake {
				d.abort()
				return
			}
			// CCS (0x14) or the encrypted 0x17 flight: the TLS 1.3 path.
			d.serverFlightAfter++
			d.maybeHandshakeDone()
		}
	})
}

// addBulk accumulates opaque-flow volume from both directions and authorises
// the cut-over once the bulk gate is crossed. Caller holds mu.
func (d *handshakeDetector) addBulk(n int) {
	d.bulkBytes += n
	if d.bulkBytes >= d.minBulk {
		d.state = migDetectReady
	}
}

// maybeHandshakeDone promotes to migDetectHandshakeDone once both peers have
// sent a post-ServerHello flight: the server flight (>=1 record after
// ServerHello) and the client flight (an uplink record begun after
// ServerHello). Caller holds mu.
func (d *handshakeDetector) maybeHandshakeDone() {
	if d.state == migDetectServerHello && d.serverFlightAfter >= 1 && d.clientFlightAfter {
		d.state = migDetectHandshakeDone
		d.downlinkSinceDone = 0
	}
}
