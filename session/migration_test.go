package session

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/lurixo/anytls-x/padding"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/logger"
)

// tlsRecord builds a single TLS record with the given outer ContentType, a
// chosen first body byte (the handshake message type for a handshake record)
// and a body of bodyLen bytes.
func tlsRecord(typ, firstBody byte, bodyLen int) []byte {
	rec := make([]byte, 5+bodyLen)
	rec[0] = typ
	rec[1], rec[2] = 0x03, 0x03
	rec[3] = byte(bodyLen >> 8)
	rec[4] = byte(bodyLen)
	if bodyLen > 0 {
		rec[5] = firstBody
	}
	return rec
}

func TestHandshakeDetectorReady(t *testing.T) {
	old := migMinBulkBytes
	migMinBulkBytes = 4096
	defer func() { migMinBulkBytes = old }()

	d := newHandshakeDetector(0)
	d.observeUplink(tlsRecord(tlsRecordHandshake, tlsHandshakeClientHello, 200)) // ClientHello
	if d.Aborted() {
		t.Fatal("aborted on a valid ClientHello")
	}
	d.observeDownlink(tlsRecord(tlsRecordHandshake, tlsHandshakeServerHello, 90)) // ServerHello
	d.observeDownlink(tlsRecord(tlsRecordAppData, 0, 1400))                       // server flight
	if d.Ready() {
		t.Fatal("ready before the client flight")
	}
	d.observeUplink(tlsRecord(tlsRecordAppData, 0, 40)) // client Finished (after ServerHello)
	if d.Ready() {
		t.Fatal("ready before the bulk gate")
	}
	d.observeDownlink(tlsRecord(tlsRecordAppData, 0, migMinBulkBytes)) // crosses the bulk gate
	if !d.Ready() {
		t.Fatal("not ready after handshake + bulk gate")
	}
}

func TestHandshakeDetectorBulkMode(t *testing.T) {
	// A non-TLS first record selects the opaque bulk gate (UoT-UDP, plaintext,
	// custom protocols) rather than aborting: the flow migrates on volume,
	// counting both directions.
	d := newHandshakeDetector(4096)
	d.observeUplink([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")) // ~38 B -> bulk mode
	if d.Aborted() {
		t.Fatal("a non-TLS flow must use the bulk gate, not abort")
	}
	if d.Ready() {
		t.Fatal("ready before the bulk gate")
	}
	d.observeDownlink(make([]byte, 4096)) // crosses 4096 total
	if !d.Ready() {
		t.Fatal("not ready after the bulk gate")
	}
}

func TestHandshakeDetectorTLSMalformedAborts(t *testing.T) {
	// A flow that opens like TLS (ClientHello) but whose downlink is not a
	// ServerHello is ruled non-migratable (stays on the mux).
	d := newHandshakeDetector(0)
	d.observeUplink(tlsRecord(tlsRecordHandshake, tlsHandshakeClientHello, 200))
	d.observeDownlink(tlsRecord(tlsRecordAppData, 0, 100)) // not a ServerHello
	if !d.Aborted() {
		t.Fatal("ClientHello followed by a non-ServerHello downlink must abort")
	}
}

func TestHandshakeDetectorTLS12Aborts(t *testing.T) {
	// A TLS 1.2 server keeps emitting cleartext-typed handshake records (0x16:
	// Certificate, …) after ServerHello, unlike TLS 1.3's encrypted 0x17 flight.
	// Only TLS 1.2 has renegotiation (a mid-stream 0x16 that would leak onto
	// carrier B), so such a flow must be ruled non-migratable.
	d := newHandshakeDetector(0)
	d.observeUplink(tlsRecord(tlsRecordHandshake, tlsHandshakeClientHello, 200))  // ClientHello
	d.observeDownlink(tlsRecord(tlsRecordHandshake, tlsHandshakeServerHello, 90)) // ServerHello
	if d.Aborted() {
		t.Fatal("aborted on the ServerHello itself")
	}
	d.observeDownlink(tlsRecord(tlsRecordHandshake, 0x0b, 1500)) // server Certificate (0x16) => TLS 1.2
	if !d.Aborted() {
		t.Fatal("a post-ServerHello cleartext handshake record (TLS 1.2) must abort migration")
	}
}

func TestHandshakeDetectorTLS13Migratable(t *testing.T) {
	// A TLS 1.3 server flight after ServerHello is encrypted application_data
	// (0x17); it must NOT be mistaken for TLS 1.2 and stays migratable.
	d := newHandshakeDetector(0)
	d.observeUplink(tlsRecord(tlsRecordHandshake, tlsHandshakeClientHello, 200))
	d.observeDownlink(tlsRecord(tlsRecordHandshake, tlsHandshakeServerHello, 90))
	d.observeDownlink(tlsRecord(tlsRecordAppData, 0, 1400)) // encrypted 1.3 flight (0x17)
	if d.Aborted() {
		t.Fatal("a TLS 1.3 (0x17) post-ServerHello flight must NOT abort")
	}
}

func TestMigPayloadGateSkipsHeader(t *testing.T) {
	// The detector must observe only the inner payload: bytes arriving before
	// BeginMigrationPayload (the anytls destination header) are ignored, so a
	// header's leading address-family byte is never misread as a record type.
	sm := &streamMig{detector: newHandshakeDetector(0)}
	sm.observeServerRead([]byte{0x01, 10, 0, 0, 1, 0x01, 0xbb}) // header: family 0x01 + ip + port
	if sm.detector.state != migDetectInit {
		t.Fatalf("pre-payload header must be ignored, state=%d", sm.detector.state)
	}
	sm.payloadStarted.Store(true)
	sm.observeServerRead(tlsRecord(tlsRecordHandshake, tlsHandshakeClientHello, 200))
	if sm.detector.state != migDetectClientHello {
		t.Fatalf("payload ClientHello must select the TLS path, state=%d", sm.detector.state)
	}
}

func TestHandshakeDetectorSplitRecords(t *testing.T) {
	// Feed the ClientHello one byte at a time: the scanner must still
	// reassemble the header and identify the handshake message type.
	d := newHandshakeDetector(0)
	ch := tlsRecord(tlsRecordHandshake, tlsHandshakeClientHello, 120)
	for i := range ch {
		d.observeUplink(ch[i : i+1])
	}
	if d.Aborted() {
		t.Fatal("aborted on a byte-split ClientHello")
	}
	if d.state != migDetectClientHello {
		t.Fatalf("state=%d, want ClientHello", d.state)
	}
}

func TestMigMinBulkResolve(t *testing.T) {
	old := migMinBulkBytes
	migMinBulkBytes = 64 * 1024
	defer func() { migMinBulkBytes = old }()

	if got := resolveMinBulk(0); got != 64*1024 {
		t.Fatalf("0 should use the default, got %d", got)
	}
	if got := resolveMinBulk(100); got != migMinBulkFloor {
		t.Fatalf("below floor should clamp to %d, got %d", migMinBulkFloor, got)
	}
	if got := resolveMinBulk(40000); got != 40000 {
		t.Fatalf("a sane value should pass through, got %d", got)
	}
}

func TestHandshakeDetectorConfiguredGate(t *testing.T) {
	// An explicit per-detector gate triggers independently of the package
	// default — the mechanism the inbound `migration_min_bulk_bytes` option uses.
	d := newHandshakeDetector(8192)
	d.observeUplink(tlsRecord(tlsRecordHandshake, tlsHandshakeClientHello, 200))
	d.observeDownlink(tlsRecord(tlsRecordHandshake, tlsHandshakeServerHello, 90))
	d.observeDownlink(tlsRecord(tlsRecordAppData, 0, 1400))
	d.observeUplink(tlsRecord(tlsRecordAppData, 0, 40))
	d.observeDownlink(tlsRecord(tlsRecordAppData, 0, 4096)) // 4096 < 8192 gate
	if d.Ready() {
		t.Fatal("ready before the configured gate")
	}
	d.observeDownlink(tlsRecord(tlsRecordAppData, 0, 4096)) // now >= 8192
	if !d.Ready() {
		t.Fatal("not ready after the configured gate")
	}
}

func TestHandshakeDetectorTLSOnly(t *testing.T) {
	// tls-only: an opaque (non-TLS) flow is ruled non-migratable (stays on mux).
	d := newHandshakeDetector(4096)
	d.tlsOnly = true
	d.observeUplink([]byte("opaque-udp-or-plaintext")) // first byte 'o' != 0x16
	if !d.Aborted() {
		t.Fatal("tls-only must abort an opaque flow")
	}
	// A TLS flow still takes the precise handshake path under tls-only.
	d2 := newHandshakeDetector(4096)
	d2.tlsOnly = true
	d2.observeUplink(tlsRecord(tlsRecordHandshake, tlsHandshakeClientHello, 200))
	if d2.Aborted() {
		t.Fatal("tls-only must still accept a TLS ClientHello")
	}
	if d2.state != migDetectClientHello {
		t.Fatalf("state=%d, want ClientHello", d2.state)
	}
}

// TestMigrationBidirectionalE2E runs a real client session and server session
// over loopback TCP, drives an inner-TLS-handshake-shaped exchange to trigger
// the rail-switch, then sends bulk in BOTH directions and asserts each side
// receives the complete byte stream intact across the mux -> carrier-B cut-over
// (no loss, dup or reorder), exercising both the downlink and uplink seams.
func TestMigrationBidirectionalE2E(t *testing.T) {
	const gate = 4096 // configured bulk gate; exercises SetMigMinBulk end-to-end

	var pad atomic.TypedValue[*padding.PaddingFactory]
	if !padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &pad) {
		t.Fatal("padding scheme")
	}
	log := logger.NOP()
	reg := NewMigRegistry()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Downlink (server -> client).
	serverHello := tlsRecord(tlsRecordHandshake, tlsHandshakeServerHello, 80)
	flight := tlsRecord(tlsRecordAppData, 0, 1500)
	margin := tlsRecord(tlsRecordAppData, 0, gate)
	downBulk := make([]byte, 256*1024)
	for i := range downBulk {
		downBulk[i] = byte(i * 7)
	}
	wantDownlink := concatBytes(serverHello, flight, margin, downBulk)

	// A simulated anytls destination header, consumed before the payload so the
	// detector never sees it (it would otherwise be misread as a TLS record).
	fakeAddr := []byte{0x01, 10, 0, 0, 1, 0x01, 0xbb}

	// Uplink (client -> server).
	clientHello := tlsRecord(tlsRecordHandshake, tlsHandshakeClientHello, 200)
	clientFinished := tlsRecord(tlsRecordAppData, 0, 40)
	upBulk := make([]byte, 128*1024)
	for i := range upBulk {
		upBulk[i] = byte(i*5 + 1)
	}
	wantUplink := concatBytes(clientHello, clientFinished, upBulk)

	carrierSeen := make(chan struct{}, 1)
	uplinkGot := make(chan []byte, 1)

	// Single accept loop: first connection is the mux session, every later
	// connection is a dedicated carrier B.
	go func() {
		first := true
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			if first {
				first = false
				c := conn
				go func() {
					srv := NewServerSession(c, func(stream *Stream) {
						// Consume the destination header first (as the real server
						// does), then mark the payload boundary so the detector
						// starts clean at the inner ClientHello.
						hdr := make([]byte, len(fakeAddr))
						if _, e := io.ReadFull(stream, hdr); e != nil {
							return
						}
						stream.BeginMigrationPayload()
						// Read the ClientHello (drives the detector to the
						// ClientHello state before any downlink record), then run
						// the downlink choreography while capturing all uplink.
						chBuf := make([]byte, len(clientHello))
						if _, e := io.ReadFull(stream, chBuf); e != nil {
							return
						}
						stream.Write(serverHello)
						stream.Write(flight)
						// Capture the rest of the uplink (Finished + the post-seam
						// upBulk) — this read path is fed by the uplink carrier.
						restBuf := make([]byte, len(clientFinished)+len(upBulk))
						upErr := make(chan error, 1)
						go func() { _, e := io.ReadFull(stream, restBuf); upErr <- e }()
						time.Sleep(250 * time.Millisecond)
						stream.Write(margin) // crosses the bulk gate -> authorises cut-over
						time.Sleep(500 * time.Millisecond)
						stream.Write(downBulk) // carried on B
						select {
						case <-upErr:
						case <-time.After(15 * time.Second):
						}
						uplinkGot <- concatBytes(chBuf, restBuf)
						stream.Close()
					}, &pad, log)
					srv.SetMigRegistry(reg)
					srv.SetMigMinBulk(gate)
					srv.Run()
					srv.Close()
				}()
			} else {
				select {
				case carrierSeen <- struct{}{}:
				default:
				}
				go MaybeAcceptCarrier(conn, reg)
			}
		}
	}()

	dialOut := func(ctx context.Context) (net.Conn, error) {
		return net.Dial("tcp", ln.Addr().String())
	}
	cli := NewClient(context.Background(), log, dialOut, &pad, 0, 0, 0, 0, 0, 0, 0)
	defer cli.Close()

	muxConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cs := NewClientSession(muxConn, &pad, log)
	cs.client = cli
	cs.migActive = true // enable the rail-switch on this client session
	cs.seq = 1
	cs.Run()
	defer cs.Close()

	stream, err := cs.OpenStream(func() {})
	if err != nil {
		t.Fatal(err)
	}
	stream.SetReadDeadline(time.Now().Add(20 * time.Second))

	// Client choreography: header -> ClientHello -> (read ServerHello) ->
	// Finished -> (read all downlink) -> uplink bulk (post-migration, on B).
	if _, err := stream.Write(fakeAddr); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write(clientHello); err != nil {
		t.Fatal(err)
	}
	gotSH := make([]byte, len(serverHello))
	if _, err := io.ReadFull(stream, gotSH); err != nil {
		t.Fatal("read ServerHello:", err)
	}
	if _, err := stream.Write(clientFinished); err != nil {
		t.Fatal(err)
	}
	downRest := make([]byte, len(flight)+len(margin)+len(downBulk))
	if _, err := io.ReadFull(stream, downRest); err != nil {
		t.Fatal("read downlink remainder:", err)
	}
	if _, err := stream.Write(upBulk); err != nil {
		t.Fatal("write uplink bulk:", err)
	}

	gotDownlink := concatBytes(gotSH, downRest)
	if !bytes.Equal(gotDownlink, wantDownlink) {
		t.Fatalf("downlink mismatch: got %d want %d (first diff %d)",
			len(gotDownlink), len(wantDownlink), firstDiff(gotDownlink, wantDownlink))
	}

	select {
	case gotUplink := <-uplinkGot:
		if !bytes.Equal(gotUplink, wantUplink) {
			t.Fatalf("uplink mismatch: got %d want %d (first diff %d)",
				len(gotUplink), len(wantUplink), firstDiff(gotUplink, wantUplink))
		}
	case <-time.After(20 * time.Second):
		t.Fatal("server did not capture the full uplink (uplink migration stalled)")
	}

	select {
	case <-carrierSeen:
		// good: a dedicated carrier B was actually established
	default:
		t.Fatal("no carrier B was established — migration did not occur")
	}
}

// TestMigrationBulkModeE2E drives a non-TLS (UoT-UDP-like) flow — its first
// payload byte is not a TLS handshake record — and asserts it migrates via the
// opaque BULK gate (no handshake parsing), with both directions intact across
// the mux -> carrier-B cut-over.
func TestMigrationBulkModeE2E(t *testing.T) {
	const gate = 4096

	var pad atomic.TypedValue[*padding.PaddingFactory]
	if !padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &pad) {
		t.Fatal("padding scheme")
	}
	log := logger.NOP()
	reg := NewMigRegistry()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	fakeAddr := []byte{0x01, 10, 0, 0, 1, 0x01, 0xbb}
	upHead := bytes.Repeat([]byte{0xAA}, 64) // first byte 0xAA != 0x16 -> bulk mode
	upBulk := make([]byte, 128*1024)
	for i := range upBulk {
		upBulk[i] = byte(i*5 + 3)
	}
	wantUplink := concatBytes(upHead, upBulk)

	downMargin := bytes.Repeat([]byte{0xBB}, gate) // crosses the bulk gate
	downBulk := make([]byte, 256*1024)
	for i := range downBulk {
		downBulk[i] = byte(i*9 + 1)
	}
	wantDownlink := concatBytes(downMargin, downBulk)

	carrierSeen := make(chan struct{}, 1)
	uplinkGot := make(chan []byte, 1)

	go func() {
		first := true
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			if first {
				first = false
				c := conn
				go func() {
					srv := NewServerSession(c, func(stream *Stream) {
						hdr := make([]byte, len(fakeAddr))
						if _, e := io.ReadFull(stream, hdr); e != nil {
							return
						}
						stream.BeginMigrationPayload()
						uh := make([]byte, len(upHead)) // opaque head -> selects bulk mode
						if _, e := io.ReadFull(stream, uh); e != nil {
							return
						}
						rest := make([]byte, len(upBulk)) // post-seam uplink, off carrier B
						upErr := make(chan error, 1)
						go func() { _, e := io.ReadFull(stream, rest); upErr <- e }()
						stream.Write(downMargin) // crosses the bulk gate -> authorises cut-over
						time.Sleep(500 * time.Millisecond)
						stream.Write(downBulk) // carried on B
						select {
						case <-upErr:
						case <-time.After(15 * time.Second):
						}
						uplinkGot <- concatBytes(uh, rest)
						stream.Close()
					}, &pad, log)
					srv.SetMigRegistry(reg)
					srv.SetMigMinBulk(gate)
					srv.Run()
					srv.Close()
				}()
			} else {
				select {
				case carrierSeen <- struct{}{}:
				default:
				}
				go MaybeAcceptCarrier(conn, reg)
			}
		}
	}()

	dialOut := func(ctx context.Context) (net.Conn, error) {
		return net.Dial("tcp", ln.Addr().String())
	}
	cli := NewClient(context.Background(), log, dialOut, &pad, 0, 0, 0, 0, 0, 0, 0)
	defer cli.Close()

	muxConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cs := NewClientSession(muxConn, &pad, log)
	cs.client = cli
	cs.migActive = true
	cs.seq = 1
	cs.Run()
	defer cs.Close()

	stream, err := cs.OpenStream(func() {})
	if err != nil {
		t.Fatal(err)
	}
	stream.SetReadDeadline(time.Now().Add(20 * time.Second))

	if _, err := stream.Write(fakeAddr); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write(upHead); err != nil {
		t.Fatal(err)
	}
	downGot := make([]byte, len(downMargin)+len(downBulk))
	if _, err := io.ReadFull(stream, downGot); err != nil {
		t.Fatal("read downlink:", err)
	}
	if _, err := stream.Write(upBulk); err != nil {
		t.Fatal("write uplink bulk:", err)
	}

	if !bytes.Equal(downGot, wantDownlink) {
		t.Fatalf("downlink mismatch: got %d want %d (first diff %d)",
			len(downGot), len(wantDownlink), firstDiff(downGot, wantDownlink))
	}
	select {
	case gotUplink := <-uplinkGot:
		if !bytes.Equal(gotUplink, wantUplink) {
			t.Fatalf("uplink mismatch: got %d want %d (first diff %d)",
				len(gotUplink), len(wantUplink), firstDiff(gotUplink, wantUplink))
		}
	case <-time.After(20 * time.Second):
		t.Fatal("server did not capture the full uplink (bulk migration stalled)")
	}
	select {
	case <-carrierSeen:
	default:
		t.Fatal("no carrier B was established — bulk migration did not occur")
	}
}

// TestMigrationHalfCloseDeliversAll guards the end-of-stream seam. After the
// cut-over the server writes a bulk downlink larger than the socket buffers and
// then ends the direction with Stream.CloseWrite() — exactly what the sing-box
// relay does when the upstream EOFs — instead of an abrupt Close. The client
// must still receive every byte followed by a clean io.EOF: the carrier is
// half-closed and drained, never reset with bytes in flight (the bug this guards
// against discarded the un-acked tail and truncated the transfer).
func TestMigrationHalfCloseDeliversAll(t *testing.T) {
	const gate = 4096

	var pad atomic.TypedValue[*padding.PaddingFactory]
	if !padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &pad) {
		t.Fatal("padding scheme")
	}
	log := logger.NOP()
	reg := NewMigRegistry()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	fakeAddr := []byte{0x01, 10, 0, 0, 1, 0x01, 0xbb}
	upHead := bytes.Repeat([]byte{0xAA}, 64) // first byte != 0x16 -> opaque bulk gate
	downMargin := bytes.Repeat([]byte{0xBB}, gate)
	downBulk := make([]byte, 2*1024*1024) // larger than the socket buffers
	for i := range downBulk {
		downBulk[i] = byte(i*7 + 1)
	}
	wantDownlink := concatBytes(downMargin, downBulk)

	carrierSeen := make(chan struct{}, 1)

	go func() {
		first := true
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			if first {
				first = false
				c := conn
				go func() {
					srv := NewServerSession(c, func(stream *Stream) {
						hdr := make([]byte, len(fakeAddr))
						if _, e := io.ReadFull(stream, hdr); e != nil {
							return
						}
						stream.BeginMigrationPayload()
						uh := make([]byte, len(upHead))
						if _, e := io.ReadFull(stream, uh); e != nil {
							return
						}
						stream.Write(downMargin) // crosses the gate -> authorises cut-over
						time.Sleep(300 * time.Millisecond)
						stream.Write(downBulk) // carried on B, partly in flight at close
						// End the downlink the way the relay does on upstream EOF:
						// a half-close, not an abrupt Close.
						stream.CloseWrite()
					}, &pad, log)
					srv.SetMigRegistry(reg)
					srv.SetMigMinBulk(gate)
					srv.Run()
					srv.Close()
				}()
			} else {
				select {
				case carrierSeen <- struct{}{}:
				default:
				}
				go MaybeAcceptCarrier(conn, reg)
			}
		}
	}()

	dialOut := func(ctx context.Context) (net.Conn, error) {
		return net.Dial("tcp", ln.Addr().String())
	}
	cli := NewClient(context.Background(), log, dialOut, &pad, 0, 0, 0, 0, 0, 0, 0)
	defer cli.Close()

	muxConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cs := NewClientSession(muxConn, &pad, log)
	cs.client = cli
	cs.migActive = true
	cs.seq = 1
	cs.Run()
	defer cs.Close()

	stream, err := cs.OpenStream(func() {})
	if err != nil {
		t.Fatal(err)
	}
	stream.SetReadDeadline(time.Now().Add(20 * time.Second))

	if _, err := stream.Write(fakeAddr); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write(upHead); err != nil {
		t.Fatal(err)
	}
	// Read the whole downlink to EOF: the half-close must deliver every byte
	// (the pre-fix abrupt close reset the carrier and truncated this).
	got, err := io.ReadAll(stream)
	if err != nil && err != io.EOF {
		t.Fatalf("read downlink: %v (got %d/%d bytes)", err, len(got), len(wantDownlink))
	}
	if !bytes.Equal(got, wantDownlink) {
		t.Fatalf("downlink truncated/mismatch: got %d want %d (first diff %d)",
			len(got), len(wantDownlink), firstDiff(got, wantDownlink))
	}
	select {
	case <-carrierSeen:
	default:
		t.Fatal("no carrier B was established — migration did not occur")
	}
}

func concatBytes(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func firstDiff(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}
