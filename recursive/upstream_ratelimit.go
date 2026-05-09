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

// defaultUpstreamMaxKeys caps the bucket map for a recursive
// resolver running against the open internet. The visited
// authoritative-server count for a healthy resolver is on the order
// of tens of thousands; 16384 leaves comfortable headroom while
// bounding worst-case memory at roughly 1 MiB. Without this cap an
// attacker that triggers many distinct upstream addresses
// (NS-graph trickery) would grow the map without bound.
const defaultUpstreamMaxKeys = 16384

// upstreamLimiter is a per-AddrPort token-bucket. Tokens replenish
// at `qps` per second up to a burst of `burst`. Take returns true
// when a token was consumed (caller may proceed) or false when the
// bucket was empty (caller should skip this server).
type upstreamLimiter struct {
	qps     float64
	burst   float64
	now     func() time.Time
	maxKeys int

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
		maxKeys: defaultUpstreamMaxKeys,
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
		if l.maxKeys > 0 && len(l.buckets) >= l.maxKeys {
			l.evictLocked(now)
		}
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

// evictLocked makes room in the bucket map. Two passes mirroring
// the source-side rate limiter: drop fully-refilled (idle) buckets
// first since they carry no useful state, then drop the single
// oldest-updated bucket if the cap is still breached. Caller holds
// l.mu.
func (l *upstreamLimiter) evictLocked(now time.Time) {
	if l.qps > 0 {
		idleFor := time.Duration(l.burst/l.qps*float64(time.Second)) + time.Second
		threshold := now.Add(-idleFor)
		for k, b := range l.buckets {
			if b.lastRefill.Before(threshold) {
				delete(l.buckets, k)
			}
		}
	}
	if l.maxKeys <= 0 || len(l.buckets) < l.maxKeys {
		return
	}
	var oldestKey netip.AddrPort
	var oldestTime time.Time
	first := true
	for k, b := range l.buckets {
		if first || b.lastRefill.Before(oldestTime) {
			oldestKey = k
			oldestTime = b.lastRefill
			first = false
		}
	}
	delete(l.buckets, oldestKey)
}
