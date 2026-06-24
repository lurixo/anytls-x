package session

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/lurixo/anytls-x/padding"
	"github.com/lurixo/anytls-x/util"
	"github.com/sagernet/sing/common/atomic"
)

const (
	// padRetries is the number of rejection-sampling attempts when
	// picking a target from the weighted list.  3 retries gives a
	// > 99.6 % hit rate when >= 30 % of the targets are feasible.
	padRetries = 3

	// maxPadTargetsStack is the capacity of the stack-allocated array
	// used for feasible-target fallback.  Must be >= the maximum
	// expected number of PadTargets entries.
	maxPadTargetsStack = 16

	// controlFramePadHint is the spare capacity reserved at the tail of a
	// control frame's pooled buffer so appendWasteFrame can write its waste
	// trailer in place (zero extra allocations) instead of allocating a fresh
	// slice. It covers the default shaping ceilings (HeadersTarget max 140,
	// PadTargets max 45); a custom scheme with larger targets simply falls
	// back to appendWasteFrame's allocation path, so correctness is unaffected.
	controlFramePadHint = 144
)

// RecordShaper has no internal synchronization: every method call and every
// direct field write (LastWrite, cfg, maxTarget) must happen while the owning
// session holds connLock. The recvLoop-side waste writers and idleLoop take
// connLock (TryLock / Lock) precisely to honor this.
type RecordShaper struct {
	conn      net.Conn
	LastWrite time.Time

	cfg        padding.RecordShaperConfig
	paddingSrc *atomic.TypedValue[*padding.PaddingFactory]
	lastCfgMd5 string

	// maxTarget caches the largest Max value across all PadTargets.
	// Frames already at or above this size skip padding entirely,
	// replacing the old fixed controlFrameThreshold = 21 constant.
	maxTarget int
}

func newRecordShaper(conn net.Conn, paddingSrc *atomic.TypedValue[*padding.PaddingFactory]) *RecordShaper {
	pf := paddingSrc.Load()
	rs := &RecordShaper{
		conn:       conn,
		LastWrite:  time.Now(),
		paddingSrc: paddingSrc,
		cfg:        pf.RecordConfig,
		lastCfgMd5: pf.Md5,
	}
	rs.maxTarget = rs.computeMaxTarget()
	return rs
}

func (rs *RecordShaper) computeMaxTarget() int {
	m := 0
	for _, t := range rs.cfg.PadTargets {
		if t.Max > m {
			m = t.Max
		}
	}
	return m
}

func (rs *RecordShaper) maybeRefreshConfig() {
	pf := rs.paddingSrc.Load()
	if pf.Md5 != rs.lastCfgMd5 {
		rs.cfg = pf.RecordConfig
		rs.lastCfgMd5 = pf.Md5
		rs.maxTarget = rs.computeMaxTarget()
	}
}

// WriteData sends data-frame bytes to the TLS connection WITHOUT a
// write deadline, matching the upstream behaviour where data-frame
// writes never had a timeout.  On a congested mobile link the TCP
// send buffer may take seconds to drain; a 5-second deadline would
// kill the session prematurely.
func (rs *RecordShaper) WriteData(b []byte) (int, error) {
	n, err := rs.conn.Write(b)
	if err == nil {
		rs.LastWrite = time.Now()
	}
	return n, err
}

// WriteInitialFlush sends the buffered initial frames (cmdSettings +
// cmdSYN + cmdPSH) shaped to resemble an H2 HEADERS frame.  In a real
// Go H2 client the first TLS record after the preface is the HEADERS
// frame for the opening request, typically 40-200 B.  This method pads
// the flush blob with a cmdWaste trailer to hit the configured
// HeadersTarget range.  Uses a write deadline like WriteControl since
// this is part of the session handshake.
func (rs *RecordShaper) WriteInitialFlush(b []byte) (int, error) {
	total := len(b)
	if padded := rs.padToHeadersTarget(b); padded != nil {
		b = padded
	}
	rs.conn.SetWriteDeadline(time.Now().Add(writeDeadline))
	_, err := rs.conn.Write(b)
	rs.conn.SetWriteDeadline(time.Time{})
	if err == nil {
		rs.LastWrite = time.Now()
	}
	return total, err
}

func (rs *RecordShaper) padToHeadersTarget(b []byte) []byte {
	rs.maybeRefreshConfig()
	target := rs.cfg.HeadersTarget
	if target.Max <= 0 {
		return nil
	}

	minTarget := len(b) + headerOverHeadSize
	if minTarget > target.Max {
		return nil
	}

	lo := target.Min
	if lo < minTarget {
		lo = minTarget
	}
	if lo > target.Max {
		return nil
	}

	var chosen int
	if lo == target.Max {
		chosen = lo
	} else {
		chosen = lo + util.FastIntn(target.Max-lo+1)
	}

	return appendWasteFrame(b, chosen)
}

// WriteControl sends control-frame bytes.  Frames smaller than the
// largest configured target are padded with a cmdWaste trailer to
// match discrete H2 control-frame sizes (SETTINGS_ACK, PING, etc.).
// All control writes use a 5-second deadline.
func (rs *RecordShaper) WriteControl(b []byte) (int, error) {
	total := len(b)
	rs.maybeRefreshConfig()
	if len(b) < rs.maxTarget {
		if padded := rs.padControlFrame(b); padded != nil {
			b = padded
		}
	}
	rs.conn.SetWriteDeadline(time.Now().Add(writeDeadline))
	_, err := rs.conn.Write(b)
	rs.conn.SetWriteDeadline(time.Time{})
	if err == nil {
		rs.LastWrite = time.Now()
	}
	return total, err
}

func (rs *RecordShaper) padControlFrame(b []byte) []byte {
	targets := rs.cfg.PadTargets
	if len(targets) == 0 {
		return nil
	}

	minTarget := len(b) + headerOverHeadSize

	// Weight-preserving rejection sampling: pick from the full target
	// list (which encodes weights by repetition), then check feasibility.
	// This preserves the H2-mimicking weight distribution instead of the
	// old filter-then-uniform-pick pattern that distorted weights when
	// small targets (e.g. 14B SETTINGS_ACK) were physically unreachable.
	nTargets := len(targets)
	var picked padding.PadTarget
	found := false
	for attempt := 0; attempt < padRetries; attempt++ {
		candidate := targets[util.FastIntn(nTargets)]
		if candidate.Max >= minTarget {
			picked = candidate
			found = true
			break
		}
	}

	// Fallback: weighted pick among feasible targets.  Uses a
	// stack-allocated array to avoid the heap allocation that the
	// old []PadTarget slice required on every call.
	if !found {
		var feasible [maxPadTargetsStack]padding.PadTarget
		nFeasible := 0
		for _, t := range targets {
			if t.Max >= minTarget && nFeasible < maxPadTargetsStack {
				feasible[nFeasible] = t
				nFeasible++
			}
		}
		if nFeasible == 0 {
			return nil
		}
		picked = feasible[util.FastIntn(nFeasible)]
	}

	var target int
	if picked.Min == picked.Max {
		target = picked.Min
	} else {
		lo := picked.Min
		if lo < minTarget {
			lo = minTarget
		}
		if lo > picked.Max {
			target = picked.Max
		} else {
			target = lo + util.FastIntn(picked.Max-lo+1)
		}
	}

	return appendWasteFrame(b, target)
}

// appendWasteFrame appends a cmdWaste frame to b so that the total length
// equals targetSize. When b already has enough spare capacity (the control
// path pre-sizes its pooled buffer, see writeControlFrame), the waste frame is
// written in place and NO allocation happens; otherwise it falls back to a
// single fresh allocation. The 4 sid bytes are zeroed explicitly: unlike the
// old make()-based path, a reused (pooled) backing array is not zero-filled,
// and the waste frame's sid must be 0 to match the original wire format.
func appendWasteFrame(b []byte, targetSize int) []byte {
	wastePayload := targetSize - len(b) - headerOverHeadSize
	if wastePayload < 0 {
		wastePayload = 0
	}
	// Clamp to the protocol per-frame max so the 2-byte length field below cannot
	// truncate on an oversized pad target.
	if wastePayload > maxFrameDataLen {
		wastePayload = maxFrameDataLen
	}

	off := len(b)
	totalSize := off + headerOverHeadSize + wastePayload

	var out []byte
	if cap(b) >= totalSize {
		out = b[:totalSize] // reuse spare capacity, zero allocations
	} else {
		out = make([]byte, totalSize)
		copy(out, b)
	}

	// Waste frame header (7 bytes): cmd(1) + sid(4) + len(2).
	out[off] = cmdWaste
	out[off+1] = 0
	out[off+2] = 0
	out[off+3] = 0
	out[off+4] = 0
	out[off+5] = byte(wastePayload >> 8)
	out[off+6] = byte(wastePayload & 0xFF)

	if wastePayload > 0 {
		util.FillRandom(out[off+headerOverHeadSize:])
	}
	return out
}

// BuildIdleFrame returns a small waste frame, or nil if the connection
// hasn't been idle long enough.  The caller writes the bytes.
func (rs *RecordShaper) BuildIdleFrame() []byte {
	rs.maybeRefreshConfig()

	if len(rs.cfg.IdleSizes) == 0 {
		return nil
	}

	// Effective idle threshold.  When idle_threshold is omitted
	// (IdleThresholdMs <= 0) a zero threshold would make the guard below
	// always false, so a waste frame would be emitted on every tick even
	// mid-transfer — contradicting this method's "idle long enough"
	// contract.  Fall back to one idle interval (IdleIntervalMs min, in
	// ms) so a frame is only emitted after at least one interval of
	// genuine quiet.  If the interval is also unset there is no sensible
	// quiet window, so emit nothing.
	thresholdMs := rs.cfg.IdleThresholdMs
	if thresholdMs <= 0 {
		thresholdMs = rs.cfg.IdleIntervalMs[0]
		if thresholdMs <= 0 {
			return nil
		}
	}
	idleThreshold := time.Duration(thresholdMs) * time.Millisecond
	if time.Since(rs.LastWrite) < idleThreshold {
		return nil
	}

	sizes := rs.cfg.IdleSizes
	size := sizes[util.FastIntn(len(sizes))]

	wastePayload := size - headerOverHeadSize
	if wastePayload < 0 {
		wastePayload = 0
	}
	// Clamp to the protocol per-frame max so the uint16 length field below cannot
	// truncate; an oversized idle_sizes entry would otherwise desync the peer.
	if wastePayload > maxFrameDataLen {
		wastePayload = maxFrameDataLen
	}

	record := make([]byte, headerOverHeadSize+wastePayload)
	record[0] = cmdWaste
	binary.BigEndian.PutUint32(record[1:5], 0)
	binary.BigEndian.PutUint16(record[5:7], uint16(wastePayload))
	if wastePayload > 0 {
		util.FillRandom(record[headerOverHeadSize:])
	}
	return record
}

func (rs *RecordShaper) IdleEnabled() bool {
	return len(rs.cfg.IdleSizes) > 0 && rs.cfg.IdleIntervalMs[1] > 0
}

func (rs *RecordShaper) IdleInterval() time.Duration {
	lo := rs.cfg.IdleIntervalMs[0]
	hi := rs.cfg.IdleIntervalMs[1]
	if lo <= 0 || hi <= 0 || lo > hi {
		return time.Duration(lo) * time.Millisecond
	}
	ms := lo + util.FastIntn(hi-lo+1)
	return time.Duration(ms) * time.Millisecond
}
