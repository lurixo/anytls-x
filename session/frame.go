package session

import (
	"encoding/binary"
)

const ( // cmds
	cmdWaste               = 0 // Paddings
	cmdSYN                 = 1 // stream open
	cmdPSH                 = 2 // data push
	cmdFIN                 = 3 // stream close, a.k.a EOF mark
	cmdSettings            = 4 // Settings (Client send to Server)
	cmdAlert               = 5 // Alert
	cmdUpdatePaddingScheme = 6 // update padding scheme
	// Since version 2
	cmdSYNACK         = 7  // Server reports to the client that the stream has been opened
	cmdHeartRequest   = 8  // Keep alive command
	cmdHeartResponse  = 9  // Keep alive command
	cmdServerSettings = 10 // Settings (Server send to client)
	// Rail-switch / 0-RTT downlink migration ("换轨"). Only ever sent when
	// migration is negotiated active (ANYTLS_MIGRATION=1 on both peers); a
	// default build neither sends nor expects these.
	cmdMigrateReady   = 11 // Server -> client: inner TLS handshake done; data = 16-byte carrier token
	cmdMigrateGo      = 12 // Server -> client: downlink barrier — last mux downlink frame for this sid
	cmdMigrateCarrier = 13 // Client -> server: first frame on the dedicated carrier B; data = token
	cmdUplinkFin      = 14 // Client -> server: uplink barrier — last mux uplink frame for this sid
)

const (
	headerOverHeadSize = 1 + 4 + 2
	maxFrameDataLen    = 0xFFFF // math.MaxUint16 — protocol max payload per frame

	// h2MaxFramePayload is the default HTTP/2 MAX_FRAME_SIZE (16384).
	// Data frames are chunked at this boundary so that each anytls
	// cmdPSH frame produces one TLS record of ≤16 KB — matching the
	// TLS record pattern of a real Go H2 DATA frame.  Go's crypto/tls
	// already splits internally at 16 KB, so this adds zero extra TCP
	// writes; the only cost is a few extra mutex acquisitions (~4 %
	// CPU on loopback, invisible on any real network link).
	h2MaxFramePayload = 16384
)

// frame defines a packet from or to be multiplexed into a single connection
type frame struct {
	cmd  byte   // 1
	sid  uint32 // 4
	data []byte // 2 + len(data)
}

func newFrame(cmd byte, sid uint32) frame {
	return frame{cmd: cmd, sid: sid}
}

type rawHeader [headerOverHeadSize]byte

func (h rawHeader) Cmd() byte {
	return h[0]
}

func (h rawHeader) StreamID() uint32 {
	return binary.BigEndian.Uint32(h[1:])
}

func (h rawHeader) Length() uint16 {
	return binary.BigEndian.Uint16(h[5:])
}
