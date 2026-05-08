package acidns

// Rate-limit middleware: a Handler middleware that throttles queries per
// source address using a token-bucket algorithm.
//
// Queries that exceed their bucket are by default refused with RCODE
// REFUSED; an option permits silent dropping instead, which more closely
// matches the behaviour of operational resolvers under stress.

import (
	"context"
	"hash/maphash"
	"net/netip"
	"sync"
	"time"

	"github.com/lestrrat-go/acidns/wire"
)

// numLimiterShards stripes the bucket map so a flood of distinct
// sources doesn't serialize through one mutex. 64 is a power of two
// to make the modulo a mask.
const numLimiterShards = 64

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

// WithRateLimitMaxKeys caps the total number of distinct source buckets
// kept in memory across all internal shards (64). The cap is applied
// per-shard as ceil(n/64), so the actual ceiling fluctuates near n
// depending on how the source addresses hash across shards. Without
// this cap a flood of spoofed source addresses fills the internal map
// until the process OOMs. When a shard reaches its cap, idle (refilled)
// buckets are evicted first, then the oldest-updated bucket within that
// shard. A non-positive value disables the cap. Defaults to 100000.
func WithRateLimitMaxKeys(n int) RateLimitOption {
	return rateLimitOptionFunc(func(c *rateLimitConfig) { c.maxKeys = n })
}

type bucket struct {
	tokens  float64
	updated time.Time
}

type limiterShard struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type limiter struct {
	inner   Handler
	qps     float64
	burst   float64
	drop    bool
	prefix  int
	maxKeys int // per-shard cap (config / numLimiterShards)
	seed    maphash.Seed
	shards  [numLimiterShards]*limiterShard
}

// NewRateLimit returns a Handler that applies the configured rate limit before
// delegating to inner.
func NewRateLimit(inner Handler, opts ...RateLimitOption) Handler {
	c := rateLimitConfig{qps: 10, burst: 20, maxKeys: 100000}
	for _, o := range opts {
		o.applyRateLimit(&c)
	}
	l := &limiter{
		inner:  inner,
		qps:    c.qps,
		burst:  float64(c.burst),
		drop:   c.drop,
		prefix: c.prefix,
		seed:   maphash.MakeSeed(),
	}
	if c.maxKeys > 0 {
		l.maxKeys = (c.maxKeys + numLimiterShards - 1) / numLimiterShards
	}
	for i := range l.shards {
		l.shards[i] = &limiterShard{buckets: make(map[string]*bucket)}
	}
	return l
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
	sh := l.shardFor(key)

	sh.mu.Lock()
	defer sh.mu.Unlock()
	b, ok := sh.buckets[key]
	if !ok {
		if l.maxKeys > 0 && len(sh.buckets) >= l.maxKeys {
			l.evictLocked(sh, now)
		}
		b = &bucket{tokens: l.burst, updated: now}
		sh.buckets[key] = b
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

func (l *limiter) shardFor(key string) *limiterShard {
	h := maphash.String(l.seed, key)
	return l.shards[h&(numLimiterShards-1)]
}

// evictLocked makes room in a single shard's bucket map. Two passes:
//
//  1. Drop any bucket that has been idle long enough to be fully refilled
//     to the burst capacity — those buckets are equivalent to a fresh
//     allocation and contain no useful state.
//  2. If the shard is still at the cap, drop the single oldest-updated
//     entry so a new key can be inserted.
//
// Caller holds sh.mu.
func (l *limiter) evictLocked(sh *limiterShard, now time.Time) {
	if l.qps > 0 {
		idleFor := time.Duration(l.burst/l.qps*float64(time.Second)) + time.Second
		threshold := now.Add(-idleFor)
		for k, b := range sh.buckets {
			if b.updated.Before(threshold) {
				delete(sh.buckets, k)
			}
		}
	}
	if l.maxKeys <= 0 || len(sh.buckets) < l.maxKeys {
		return
	}
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, b := range sh.buckets {
		if first || b.updated.Before(oldestTime) {
			oldestKey = k
			oldestTime = b.updated
			first = false
		}
	}
	delete(sh.buckets, oldestKey)
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
