// Package ratelimit is a Handler middleware that throttles queries per
// source address using a token-bucket algorithm.
//
// Queries that exceed their bucket are by default refused with RCODE
// REFUSED; an option permits silent dropping instead, which more closely
// matches the behaviour of operational resolvers under stress.
package ratelimit

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/lestrrat-go/acidns/dnsserver"
	"github.com/lestrrat-go/acidns/wire"
)

// Option configures the limiter.
type Option interface{ applyRL(*config) }

type optionFunc func(*config)

func (f optionFunc) applyRL(c *config) { f(c) }

type config struct {
	qps    float64
	burst  int
	drop   bool
	keyer  func(netip.Addr) string
	prefix int // CIDR mask applied before keying (e.g. 24 → group v4 by /24)
}

// WithQPS sets the average queries-per-second rate per source. Defaults to
// 10 qps.
func WithQPS(qps float64) Option { return optionFunc(func(c *config) { c.qps = qps }) }

// WithBurst sets how many tokens a fresh source begins with. Defaults to
// 20 — twice WithQPS by convention.
func WithBurst(n int) Option { return optionFunc(func(c *config) { c.burst = n }) }

// WithDrop silences over-budget queries instead of returning REFUSED.
func WithDrop() Option { return optionFunc(func(c *config) { c.drop = true }) }

// WithGroupPrefix coalesces sources by the given CIDR mask before keying
// the bucket — useful so a single misbehaving /24 isn't permitted to
// multiply a budget by 256.
func WithGroupPrefix(maskBits int) Option {
	return optionFunc(func(c *config) { c.prefix = maskBits })
}

type bucket struct {
	tokens  float64
	updated time.Time
}

type limiter struct {
	inner   dnsserver.Handler
	qps     float64
	burst   float64
	drop    bool
	prefix  int
	mu      sync.Mutex
	buckets map[string]*bucket
}

// New returns a Handler that applies the configured rate limit before
// delegating to inner.
func New(inner dnsserver.Handler, opts ...Option) dnsserver.Handler {
	c := config{qps: 10, burst: 20}
	for _, o := range opts {
		o.applyRL(&c)
	}
	return &limiter{
		inner:   inner,
		qps:     c.qps,
		burst:   float64(c.burst),
		drop:    c.drop,
		prefix:  c.prefix,
		buckets: make(map[string]*bucket),
	}
}

func (l *limiter) ServeDNS(ctx context.Context, w dnsserver.ResponseWriter, q wire.Message) {
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

func (l *limiter) key(src netip.Addr) string {
	if l.prefix <= 0 {
		return src.String()
	}
	if pfx, err := src.Prefix(l.prefix); err == nil {
		return pfx.String()
	}
	return src.String()
}

func (l *limiter) refuse(w dnsserver.ResponseWriter, q wire.Message) {
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
