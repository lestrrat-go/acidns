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
	"time"

	"github.com/lestrrat-go/acidns/internal/shardbucket"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/option/v3"
)

// RateLimitOption configures the limiter.
type RateLimitOption interface {
	option.Interface
	rateLimitOption()
}

type rateLimitOption struct{ option.Interface }

func (rateLimitOption) rateLimitOption() {}

type rateLimitConfig struct {
	qps      float64
	burst    int
	drop     bool
	v4Prefix int // CIDR mask applied to IPv4 sources (0 disables; 1..32 valid)
	v6Prefix int // CIDR mask applied to IPv6 sources (0 disables; 1..128 valid)
	maxKeys  int
}

type identRateLimitQPS struct{}
type identRateLimitBurst struct{}
type identRateLimitDrop struct{}
type identRateLimitV4Prefix struct{}
type identRateLimitV6Prefix struct{}
type identRateLimitMaxKeys struct{}

// WithRateLimitQPS sets the average queries-per-second rate per source. Defaults to
// 10 qps.
func WithRateLimitQPS(qps float64) RateLimitOption {
	return rateLimitOption{option.New(identRateLimitQPS{}, qps)}
}

// WithRateLimitBurst sets how many tokens a fresh source begins with. Defaults to
// 20 — twice WithRateLimitQPS by convention.
func WithRateLimitBurst(n int) RateLimitOption {
	return rateLimitOption{option.New(identRateLimitBurst{}, n)}
}

// WithRateLimitDrop silences over-budget queries instead of returning REFUSED.
// Pass true to drop, false to reply REFUSED (the default).
func WithRateLimitDrop(v bool) RateLimitOption {
	return rateLimitOption{option.New(identRateLimitDrop{}, v)}
}

// WithRateLimitIPv4Prefix coalesces IPv4 sources by the given CIDR mask
// before keying the bucket — useful so a single misbehaving /24 isn't
// permitted to multiply a budget by 256. The mask is clamped to [0, 32]
// at construction; 0 (the default) disables prefix grouping for IPv4.
func WithRateLimitIPv4Prefix(maskBits int) RateLimitOption {
	return rateLimitOption{option.New(identRateLimitV4Prefix{}, maskBits)}
}

// WithRateLimitIPv6Prefix coalesces IPv6 sources by the given CIDR mask
// before keying the bucket. /48 or /64 are the typical aggregation
// boundaries on the public internet. The mask is clamped to [0, 128]
// at construction; 0 (the default) disables prefix grouping for IPv6.
func WithRateLimitIPv6Prefix(maskBits int) RateLimitOption {
	return rateLimitOption{option.New(identRateLimitV6Prefix{}, maskBits)}
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
	return rateLimitOption{option.New(identRateLimitMaxKeys{}, n)}
}

type bucket struct {
	tokens  float64
	updated time.Time
}

type limiter struct {
	inner    Handler
	qps      float64
	burst    float64
	drop     bool
	v4Prefix int
	v6Prefix int
	maxKeys  int // per-shard cap derived from total cap
	pool     *shardbucket.Pool[bucket]
}

// NewRateLimit returns a Handler that applies the configured rate limit before
// delegating to inner.
func NewRateLimit(inner Handler, opts ...RateLimitOption) Handler {
	c := rateLimitConfig{qps: 10, burst: 20, maxKeys: 100000}
	for _, o := range opts {
		switch o.Ident() {
		case identRateLimitQPS{}:
			c.qps = option.MustGet[float64](o)
		case identRateLimitBurst{}:
			c.burst = option.MustGet[int](o)
		case identRateLimitDrop{}:
			c.drop = option.MustGet[bool](o)
		case identRateLimitV4Prefix{}:
			c.v4Prefix = option.MustGet[int](o)
		case identRateLimitV6Prefix{}:
			c.v6Prefix = option.MustGet[int](o)
		case identRateLimitMaxKeys{}:
			c.maxKeys = option.MustGet[int](o)
		}
	}
	l := &limiter{
		inner:    inner,
		qps:      c.qps,
		burst:    float64(c.burst),
		drop:     c.drop,
		v4Prefix: clampPrefix(c.v4Prefix, 32),
		v6Prefix: clampPrefix(c.v6Prefix, 128),
		maxKeys:  shardbucket.PerShardCap(c.maxKeys),
		pool:     shardbucket.New[bucket](),
	}
	return l
}

func (l *limiter) ServeDNS(ctx context.Context, w ResponseWriter, q wire.Message) {
	// Unmap v4-mapped sources before bucketing — otherwise every IPv4
	// client on a dual-stack listener collapses into one shared `::`-rooted
	// bucket and a single attacker starves all of them (or vice versa).
	if !l.allow(w.RemoteAddr().Addr().Unmap()) {
		if l.drop {
			return
		}
		writeRefused(w, q)
		return
	}
	l.inner.ServeDNS(ctx, w, q)
}

func (l *limiter) allow(src netip.Addr) bool {
	key := l.key(src)
	now := time.Now()
	sh := l.pool.ShardFor(key)

	sh.Mu.Lock()
	defer sh.Mu.Unlock()
	b, ok := sh.Buckets[key]
	if !ok {
		if l.maxKeys > 0 && len(sh.Buckets) >= l.maxKeys {
			l.evictLocked(sh, now)
		}
		b = &bucket{tokens: l.burst, updated: now}
		sh.Buckets[key] = b
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

// evictLocked makes room in a single shard's bucket map. Two passes:
//
//  1. Drop any bucket that has been idle long enough to be fully refilled
//     to the burst capacity — those buckets are equivalent to a fresh
//     allocation and contain no useful state.
//  2. If the shard is still at the cap, drop the single oldest-updated
//     entry so a new key can be inserted.
//
// Caller holds sh.mu.
//
// The two passes are O(per-shard cap) per cache miss once the cap is
// hit. That's tolerable because NewRateLimit standalone is not the
// designed defence against spoofed-source floods — [NewRRL] is, and
// RRL defaults to /24 + /56 prefix grouping ([NewRRL] line 172-173)
// which keeps its bucket map far below the cap in realistic traffic.
// The documented composition contract is at [NewRRL]'s package
// comment: "NewRRL alone is sufficient against amplification;
// NewRateLimit alone is not, because spoofed sources defeat
// per-source query budgets." Operators who run NewRateLimit on an
// internet-exposed listener without also running NewRRL (or without
// WithRateLimitIPv4Prefix / WithRateLimitIPv6Prefix to bound the
// keyspace) have a deeper defence gap than the eviction cost.
func (l *limiter) evictLocked(sh *shardbucket.Shard[bucket], now time.Time) {
	if l.qps > 0 {
		idleFor := time.Duration(l.burst/l.qps*float64(time.Second)) + time.Second
		threshold := now.Add(-idleFor)
		for k, b := range sh.Buckets {
			if b.updated.Before(threshold) {
				delete(sh.Buckets, k)
			}
		}
	}
	if l.maxKeys <= 0 || len(sh.Buckets) < l.maxKeys {
		return
	}
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, b := range sh.Buckets {
		if first || b.updated.Before(oldestTime) {
			oldestKey = k
			oldestTime = b.updated
			first = false
		}
	}
	delete(sh.Buckets, oldestKey)
}

func (l *limiter) key(src netip.Addr) string {
	bits := l.v4Prefix
	if src.Is6() && !src.Is4In6() {
		bits = l.v6Prefix
	}
	if bits <= 0 {
		return src.String()
	}
	pfx, err := src.Prefix(bits)
	if err != nil {
		// Should not happen — bits is clamped to family-max at NewRateLimit
		// time. If a future refactor breaks the invariant we fall back to
		// per-address keying rather than silently disabling the limiter.
		return src.String()
	}
	return pfx.String()
}

// clampPrefix bounds maskBits into [0, upper]. Negative values become 0
// (disabled); values above upper are clamped to upper so an operator who
// requests /128 on an IPv4-only deployment gets per-address keying
// instead of silent fall-through to no grouping at all.
func clampPrefix(maskBits, upper int) int {
	if maskBits < 0 {
		return 0
	}
	if maskBits > upper {
		return upper
	}
	return maskBits
}
