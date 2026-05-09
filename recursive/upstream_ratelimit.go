package recursive

// Per-upstream rate limiting. The recursive resolver issues queries
// to authoritative servers; without a cap it can hammer a single
// server during a burst (e.g., a million distinct CNAME chases all
// rooted at the same TLD). A leaky-bucket-per-AddrPort policy bounds
// the rate without blocking unrelated upstreams.
//
// Default config holds NO limit — the resolver only enforces a cap
// when [WithUpstreamRateLimit] is set. The token-bucket rate counts
// queries per second per upstream IP+port.

import (
	"net/netip"
	"sync"
	"time"
)

// upstreamLimiter is a per-AddrPort token-bucket. Tokens replenish
// at `qps` per second up to a burst of `burst`. Take returns true
// when a token was consumed (caller may proceed) or false when the
// bucket was empty (caller should skip this server).
type upstreamLimiter struct {
	qps   float64
	burst float64
	now   func() time.Time

	mu      sync.Mutex
	buckets map[netip.AddrPort]*tokenBucket
}

type tokenBucket struct {
	tokens     float64
	lastRefill time.Time
}

func newUpstreamLimiter(qps float64, burst float64, now func() time.Time) *upstreamLimiter {
	if now == nil {
		now = time.Now
	}
	return &upstreamLimiter{
		qps:     qps,
		burst:   burst,
		now:     now,
		buckets: make(map[netip.AddrPort]*tokenBucket),
	}
}

// Take attempts to consume one token for addr. Returns true on
// success. A non-positive qps disables the limiter (Take always
// succeeds). The first Take for any addr starts the bucket full
// at burst tokens.
func (l *upstreamLimiter) Take(addr netip.AddrPort) bool {
	if l == nil || l.qps <= 0 {
		return true
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[addr]
	if !ok {
		b = &tokenBucket{tokens: l.burst, lastRefill: now}
		l.buckets[addr] = b
	}
	// Refill since last access.
	elapsed := now.Sub(b.lastRefill).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * l.qps
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.lastRefill = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
