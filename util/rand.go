package util

import (
	"encoding/binary"
	mrand "math/rand/v2"
)

// FillRandom fills b with pseudo-random bytes using math/rand/v2's
// auto-seeded ChaCha8 PRNG. This is suitable for padding and waste
// bytes that do not require cryptographic randomness. Zero heap
// allocations; no syscalls after program init.
func FillRandom(b []byte) {
	for len(b) >= 8 {
		binary.LittleEndian.PutUint64(b, mrand.Uint64())
		b = b[8:]
	}
	if len(b) > 0 {
		val := mrand.Uint64()
		for i := range b {
			b[i] = byte(val)
			val >>= 8
		}
	}
}

// FastIntn returns a uniformly distributed, non-negative pseudo-random
// int in [0, n) using math/rand/v2's auto-seeded ChaCha8 PRNG. Like the
// rest of this file it is for traffic shaping (padding lengths, split
// points, jitter) — values that are NOT key material — so it deliberately
// avoids crypto/rand: a syscall-free, allocation-free, already-unbiased
// PRNG is both faster and, for this use, no weaker against traffic
// analysis. For n <= 1 it returns 0 (math/rand/v2.IntN panics on n <= 0).
func FastIntn(n int) int {
	if n <= 1 {
		return 0
	}
	return mrand.IntN(n)
}
