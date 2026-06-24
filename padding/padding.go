package padding

import (
	"crypto/md5"
	"fmt"
	"strconv"
	"strings"

	"github.com/lurixo/anytls-x/util"
	"github.com/sagernet/sing/common/atomic"
)

// DefaultPaddingScheme mimics a Caddy (Go stdlib) HTTP/2 server.
//
//   - Auth packet padding: fixed 35 bytes, so the total auth packet
//     (34 + 35 = 69 B) exactly matches a real H2 connection preface
//     (24 B magic + 45 B SETTINGS = 69 B).  The fixed value produces
//     a delta-function distribution identical to a real Caddy server,
//     whereas a random range would be trivially distinguishable.
//   - Control frame targets: H2 discrete sizes including SETTINGS_ACK
//     (≈14 B), PING (17 B), SETTINGS (45 B), WINDOW_UPDATE (22-30 B),
//     weighted by typical Caddy frequency.
//   - Headers target: the initial flush (cmdSettings+cmdSYN+cmdPSH)
//     is shaped to 90-140 B, matching a Go H2 HEADERS frame for a
//     typical HTTPS request with HPACK compression.
//   - Idle injection: OFF.  A real Caddy H2 server sends no H2 PING
//     frames during idle; TCP keepalives (15 s) are at layer 4 and
//     produce no TLS records.
//   - WINDOW_UPDATE injection: every ~128 KB of received DATA, a 13 B
//     waste frame (matching H2 WINDOW_UPDATE wire size) is emitted.
//     This reproduces the DATA,DATA,...,WND_UPD,DATA,... pattern of
//     real Go H2 flow control.
var DefaultPaddingScheme = []byte(`pad_dist=35-35:100
pad_targets=14,14,17,17,17,45,22-30
headers_target=90-140
wnd_update_interval=131072`)

// PaddingBucket defines a weighted range for multi-modal padding sampling.
// Multiple buckets create a distribution with several peaks, avoiding the
// flat uniform fingerprint that a single fixed range produces.
type PaddingBucket struct {
	Min    int
	Max    int
	Weight int
}

// PadTarget defines a single padding target: either a fixed value or
// a range. Used by padControlFrame to select the output size for small
// control frames (cmdSYN, cmdFIN, etc.).
type PadTarget struct {
	Min int
	Max int
}

// RecordShaperConfig holds tunable parameters for TLS record-level
// traffic shaping. Parsed from PaddingScheme keys.
type RecordShaperConfig struct {
	PadTargets      []PadTarget // target sizes for padding control frames
	HeadersTarget   PadTarget   // target size for initial flush (H2 HEADERS)
	IdleSizes       []int       // record sizes for idle keepalive injection
	IdleIntervalMs  [2]int      // [min, max] ms between idle injections
	IdleThresholdMs int         // ms of silence before considering connection idle

	// WndUpdateInterval is the number of received DATA bytes between
	// WINDOW_UPDATE-like waste frame injections (0 = disabled).
	// Default: 131072 (~128 KB, matching Go H2 flow control increments).
	WndUpdateInterval int
}

// DefaultRecordShaperConfig returns the built-in configuration.
//
// Target sizes represent the desired total wire length (payload + waste
// header + waste body) of a padded control frame.  The minimum
// achievable padded size is 14 B (7 B smallest frame + 7 B waste
// header with 0-byte body).  Targets below 14 are unreachable and
// would waste rejection-sampling attempts, so the smallest target
// is 14 B (approximating a real H2 SETTINGS_ACK at 13 B — the 1 B
// difference is within normal TLS record overhead variance).
//
// Weight is encoded by repetition: entries that appear more often in
// the list are selected more frequently by the rejection sampler.
func DefaultRecordShaperConfig() RecordShaperConfig {
	return RecordShaperConfig{
		PadTargets: []PadTarget{
			{14, 14}, // ≈H2 SETTINGS_ACK (9 header + 0 payload + TLS framing)
			{14, 14}, // doubled weight — very common in Caddy
			{17, 17}, // H2 PING frame (8 payload + 9 header)
			{17, 17}, // doubled weight
			{17, 17}, // tripled — most common control frame
			{45, 45}, // H2 SETTINGS (6 params × 6 B + 9 header)
			{22, 30}, // bundled SETTINGS_ACK + WINDOW_UPDATE
		},
		HeadersTarget:     PadTarget{90, 140}, // Go H2 HEADERS for typical GET
		WndUpdateInterval: 131072,             // ~128 KB
	}
}

type PaddingFactory struct {
	RawScheme []byte
	Md5       string

	// PadBuckets holds the weighted bucket distribution used by
	// SamplePaddingLen for auth-packet padding. A nil/empty slice
	// means no padding is generated.
	PadBuckets []PaddingBucket

	totalWeight int

	// RecordConfig holds parameters for the TLS record-level traffic
	// shaper. Parsed from the PaddingScheme; falls back to
	// DefaultRecordShaperConfig when absent.
	RecordConfig RecordShaperConfig
}

func UpdatePaddingScheme(rawScheme []byte, to *atomic.TypedValue[*PaddingFactory]) bool {
	if p := NewPaddingFactory(rawScheme); p != nil {
		to.Store(p)
		return true
	}
	return false
}

func NewPaddingFactory(rawScheme []byte) *PaddingFactory {
	p := &PaddingFactory{
		RawScheme: rawScheme,
		Md5:       fmt.Sprintf("%x", md5.Sum(rawScheme)),
	}
	scheme := util.StringMapFromBytes(rawScheme)
	if len(scheme) == 0 {
		return nil
	}

	// Parse pad_dist — format: "min-max:weight,min-max:weight,..."
	// Falls back to a sensible default if missing or malformed.
	if dist, ok := scheme["pad_dist"]; ok {
		p.PadBuckets = parseBuckets(dist)
	}
	if len(p.PadBuckets) == 0 {
		p.PadBuckets = []PaddingBucket{
			{35, 35, 100},
		}
	}
	for _, b := range p.PadBuckets {
		p.totalWeight += b.Weight
	}

	p.RecordConfig = parseRecordShaperConfig(scheme)

	return p
}

func parseRecordShaperConfig(scheme util.StringMap) RecordShaperConfig {
	cfg := DefaultRecordShaperConfig()

	if s, ok := scheme["pad_targets"]; ok {
		if targets := parsePadTargets(s); len(targets) > 0 {
			cfg.PadTargets = targets
		}
	}

	if s, ok := scheme["headers_target"]; ok {
		if lo, hi, ok := parseRange(s); ok {
			cfg.HeadersTarget = PadTarget{lo, hi}
		}
	}

	if s, ok := scheme["idle_sizes"]; ok {
		if sizes := parseIntList(s); len(sizes) > 0 {
			cfg.IdleSizes = sizes
		}
	}

	if s, ok := scheme["idle_interval"]; ok {
		if lo, hi, ok := parseRange(s); ok {
			cfg.IdleIntervalMs = [2]int{lo, hi}
		}
	}

	if s, ok := scheme["idle_threshold"]; ok {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			cfg.IdleThresholdMs = v
		}
	}

	if s, ok := scheme["wnd_update_interval"]; ok {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			cfg.WndUpdateInterval = v
		}
	}

	return cfg
}

func parsePadTargets(s string) []PadTarget {
	var targets []PadTarget
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		rangeParts := strings.SplitN(part, "-", 2)
		if len(rangeParts) == 1 {
			v, err := strconv.Atoi(rangeParts[0])
			if err != nil || v <= 0 {
				continue
			}
			targets = append(targets, PadTarget{v, v})
		} else {
			lo, err1 := strconv.Atoi(rangeParts[0])
			hi, err2 := strconv.Atoi(rangeParts[1])
			if err1 != nil || err2 != nil || lo <= 0 || hi <= 0 {
				continue
			}
			if lo > hi {
				lo, hi = hi, lo
			}
			targets = append(targets, PadTarget{lo, hi})
		}
	}
	return targets
}

func parseRange(s string) (int, int, bool) {
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	lo, err1 := strconv.Atoi(parts[0])
	hi, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || lo <= 0 || hi <= 0 {
		return 0, 0, false
	}
	if lo > hi {
		lo, hi = hi, lo
	}
	return lo, hi, true
}

func parseIntList(s string) []int {
	var result []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if v, err := strconv.Atoi(part); err == nil && v > 0 {
			result = append(result, v)
		}
	}
	return result
}

func parseBuckets(s string) []PaddingBucket {
	var buckets []PaddingBucket
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		colonIdx := strings.LastIndex(part, ":")
		if colonIdx < 0 {
			continue
		}
		rangePart := part[:colonIdx]
		weightPart := part[colonIdx+1:]

		weight, err := strconv.Atoi(weightPart)
		if err != nil || weight <= 0 {
			continue
		}

		rangeParts := strings.SplitN(rangePart, "-", 2)
		if len(rangeParts) != 2 {
			continue
		}
		bMin, err1 := strconv.Atoi(rangeParts[0])
		bMax, err2 := strconv.Atoi(rangeParts[1])
		if err1 != nil || err2 != nil || bMin <= 0 || bMax <= 0 {
			continue
		}
		if bMin > bMax {
			bMin, bMax = bMax, bMin
		}
		buckets = append(buckets, PaddingBucket{Min: bMin, Max: bMax, Weight: weight})
	}
	return buckets
}

func (p *PaddingFactory) SamplePaddingLen() int {
	if len(p.PadBuckets) == 0 || p.totalWeight <= 0 {
		return 0
	}

	pick := util.FastIntn(p.totalWeight)
	var bucket PaddingBucket
	for _, b := range p.PadBuckets {
		pick -= b.Weight
		if pick < 0 {
			bucket = b
			break
		}
	}

	if bucket.Min == bucket.Max {
		return bucket.Min
	}
	span := bucket.Max - bucket.Min + 1
	result := bucket.Min + util.FastIntn(span)
	// Hard cap: the auth packet (34 + padding) must fit in one initial
	// TLS record.  Worst case (TLS 1.2 AES-CBC-SHA256) holds 1151
	// bytes of application data.  1100 stays safely below that.
	if result > 1100 {
		result = 1100
	}
	return result
}
