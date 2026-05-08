package acidns

// Rate-limit middleware: a Handler middleware that throttles queries per
// source address using a token-bucket algorithm.
//
// Queries that exceed their bucket are by default refused with RCODE
// REFUSED; an option permits silent dropping instead, which more closely
// matches the behaviour of operational resolvers under stress.

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/lestrrat-go/acidns/wire"
)

// RateLimitOption configures the limiter.
type RateLimitOption interface{ applyRateLimit(*rateLimitConfig) }

type rateLimitOptionFunc func(*rateLimitConfig)

func (f rateLimitOptionFunc) applyRateLimit(c *rateLimitConfig) { f(c) }

type rateLimitConfig struct {
	qps     float64
	burst   int
	drop    bool
	prefix  int // CIDR mask applied before keying (e.g. 24 → group v4 by /24)
	maxKeys int
}

// WithRateLimitQPS sets the average queries-per-second rate per source. Defaults to
// 10 qps.
func WithRateLimitQPS(qps float64) RateLimitOption {
	return rateLimitOptionFunc(func(c *rateLimitConfig) { c.qps = qps })
}

// WithRateLimitBurst sets how many tokens a fresh source begins with. Defaults to
// 20 — twice WithRateLimitQPS by convention.
func WithRateLimitBurst(n int) RateLimitOption {
	return rateLimitOptionFunc(func(c *rateLimitConfig) { c.burst = n })
}

// WithRateLimitDrop silences over-budget queries instead of returning REFUSED.
func WithRateLimitDrop() RateLimitOption {
	return rateLimitOptionFunc(func(c *rateLimitConfig) { c.drop = true })
}

// WithRateLimitGroupPrefix coalesces sources by the given CIDR mask before keying
// the bucket — useful so a single misbehaving /24 isn't permitted to
// multiply a budget by 256.
func WithRateLimitGroupPrefix(maskBits int) RateLimitOption {
	return rateLimitOptionFunc(func(c *rateLimitConfig) { c.prefix = maskBits })
}

// WithRateLimitMaxKeys caps how many distinct source buckets are kept in
// memory. Without this cap, a flood of spoofed source addresses fills the
// internal map until the process OOMs — defeating the very protection the
// limiter is supposed to provide. When the cap is reached, idle (refilled)
// buckets are evicted first, then the oldest-updated bucket. A non-positive
// value disables the cap. Defaults to 100000.
func WithRateLimitMaxKeys(n int) RateLimitOption {
	return rateLimitOptionFunc(func(c *rateLimitConfig) { c.maxKeys = n })
}

type bucket struct {
	tokens  float64
	updated time.Time
}

type limiter struct {
	inner   Handler
	qps     float64
	burst   float64
	drop    bool
	prefix  int
	maxKeys int
	mu      sync.Mutex
	buckets map[string]*bucket
}

// NewRateLimit returns a Handler that applies the configured rate limit before
// delegating to inner.
func NewRateLimit(inner Handler, opts ...RateLimitOption) Handler {
	c := rateLimitConfig{qps: 10, burst: 20, maxKeys: 100000}
	for _, o := range opts {
		o.applyRateLimit(&c)
	}
	return &limiter{
		inner:   inner,
		qps:     c.qps,
		burst:   float64(c.burst),
		drop:    c.drop,
		prefix:  c.prefix,
		maxKeys: c.maxKeys,
		buckets: make(map[string]*bucket),
	}
}

func (l *limiter) ServeDNS(ctx context.Context, w ResponseWriter, q wire.Message) {
	if !l.allow(w.RemoteAddr().Addr()) {
		if l.drop {
			return
		}
		l.refuse(w, q)
		return
	}
	l.inner.ServeDNS(ctx, w, q)
}

func (l *limiter) allow(src netip.Addr) bool {
	key := l.key(src)
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		if l.maxKeys > 0 && len(l.buckets) >= l.maxKeys {
			l.evictLocked(now)
		}
		b = &bucket{tokens: l.burst, updated: now}
		l.buckets[key] = b
	}
	elapsed := now.Sub(b.updated).Seconds()
	b.tokens += elapsed * l.qps
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.updated = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// evictLocked makes room in the bucket map. Two passes:
//
//  1. Drop any bucket that has been idle long enough to be fully refilled
//     to the burst capacity — those buckets are equivalent to a fresh
//     allocation and contain no useful state.
//  2. If the map is still at the cap, drop the single oldest-updated entry
//     so a new key can be inserted.
//
// Caller holds l.mu.
func (l *limiter) evictLocked(now time.Time) {
	if l.qps > 0 {
		// Time required to refill an empty bucket to full burst.
		idleFor := time.Duration(l.burst/l.qps*float64(time.Second)) + time.Second
		threshold := now.Add(-idleFor)
		for k, b := range l.buckets {
			if b.updated.Before(threshold) {
				delete(l.buckets, k)
			}
		}
	}
	if l.maxKeys <= 0 || len(l.buckets) < l.maxKeys {
		return
	}
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, b := range l.buckets {
		if first || b.updated.Before(oldestTime) {
			oldestKey = k
			oldestTime = b.updated
			first = false
		}
	}
	delete(l.buckets, oldestKey)
}

func (l *limiter) key(src netip.Addr) string {
	if l.prefix <= 0 {
		return src.String()
	}
	if pfx, err := src.Prefix(l.prefix); err == nil {
		return pfx.String()
	}
	return src.String()
}

func (l *limiter) refuse(w ResponseWriter, q wire.Message) {
	b := wire.NewBuilder().
		ID(q.ID()).
		Response(true).
		RecursionDesired(q.Flags().RecursionDesired()).
		RCODE(wire.RCODERefused)
	if len(q.Questions()) > 0 {
		b = b.Question(q.Questions()[0])
	}
	resp, err := b.Build()
	if err != nil {
		return
	}
	_ = w.WriteMsg(resp)
}
