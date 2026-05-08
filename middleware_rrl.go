package acidns

// Response Rate Limiting (RRL): a Handler middleware that throttles
// response emission by source + response classification, with slip-rate
// truncation so legitimate clients can still fall back to TCP. RRL is
// the canonical mitigation for DNS amplification attacks: an attacker
// spoofs the source IP of a victim and asks for an answer whose
// response is much larger than the query, multiplying their bandwidth
// onto the victim. Per-source rate limiting alone (NewRateLimit) is not
// enough — it caps queries per source, but with spoofed sources every
// query has a "fresh" source. RRL keys on the *response* tuple, so an
// attacker amplifying off any single victim hits the bucket regardless
// of which spoofed source was used.

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/lestrrat-go/acidns/wire"
)

// RRLOption configures the limiter.
type RRLOption interface{ applyRRL(*rrlConfig) }

type rrlOptionFunc func(*rrlConfig)

func (f rrlOptionFunc) applyRRL(c *rrlConfig) { f(c) }

type rrlConfig struct {
	respPerSecond   float64
	nxdomainsPerS   float64
	errorsPerSecond float64
	burst           int
	slip            int
	v4Prefix        int
	v6Prefix        int
	maxKeys         int
}

// WithRRLResponsesPerSecond sets the steady-state limit on positive
// answers per (source-prefix, response-name) pair. Defaults to 10.
func WithRRLResponsesPerSecond(qps float64) RRLOption {
	return rrlOptionFunc(func(c *rrlConfig) { c.respPerSecond = qps })
}

// WithRRLNXDOMAINsPerSecond sets the limit on negative (NXDOMAIN /
// NoData) answers per (source-prefix, response-name) pair. Defaults
// to 5 — operationally lower than positive responses because a flood
// of negative answers points strongly at random-subdomain attacks.
func WithRRLNXDOMAINsPerSecond(qps float64) RRLOption {
	return rrlOptionFunc(func(c *rrlConfig) { c.nxdomainsPerS = qps })
}

// WithRRLErrorsPerSecond sets the limit on SERVFAIL / REFUSED / other
// error responses per source-prefix. Defaults to 5.
func WithRRLErrorsPerSecond(qps float64) RRLOption {
	return rrlOptionFunc(func(c *rrlConfig) { c.errorsPerSecond = qps })
}

// WithRRLBurst sets the bucket size — how many tokens a fresh bucket
// starts with. Defaults to 2× the steady-state rate.
func WithRRLBurst(n int) RRLOption {
	return rrlOptionFunc(func(c *rrlConfig) { c.burst = n })
}

// WithRRLSlipRate sets how often a blocked response is converted into
// a TC=1 truncated reply (rather than silently dropped). 1 means every
// blocked response is slipped; 2 means every other; 0 disables
// slipping (always drop). Defaults to 2 — matches BIND's default and
// is RFC-compatible with RFC 5358 reflection guidance.
func WithRRLSlipRate(n int) RRLOption {
	return rrlOptionFunc(func(c *rrlConfig) { c.slip = n })
}

// WithRRLIPv4Prefix groups IPv4 sources by the given CIDR mask.
// Defaults to /24 — RRL operates on aggregations, not single hosts,
// because spoofed sources are usually drawn from large blocks.
func WithRRLIPv4Prefix(maskBits int) RRLOption {
	return rrlOptionFunc(func(c *rrlConfig) { c.v4Prefix = maskBits })
}

// WithRRLIPv6Prefix groups IPv6 sources by the given CIDR mask.
// Defaults to /56.
func WithRRLIPv6Prefix(maskBits int) RRLOption {
	return rrlOptionFunc(func(c *rrlConfig) { c.v6Prefix = maskBits })
}

// WithRRLMaxKeys caps the number of distinct (source, name, class)
// buckets retained in memory. Once at the cap, idle (refilled)
// buckets are evicted first; if still at the cap, the oldest-updated
// bucket is dropped. Defaults to 100000.
func WithRRLMaxKeys(n int) RRLOption {
	return rrlOptionFunc(func(c *rrlConfig) { c.maxKeys = n })
}

type rrlBucket struct {
	tokens      float64
	updated     time.Time
	slipCounter int
}

type rrl struct {
	inner           Handler
	respPerSecond   float64
	nxdomainsPerS   float64
	errorsPerSecond float64
	burst           float64
	slip            int
	v4Prefix        int
	v6Prefix        int
	maxKeys         int
	mu              sync.Mutex
	buckets         map[string]*rrlBucket
}

// NewRRL returns a Handler that wraps inner with RFC-style Response
// Rate Limiting. The middleware classifies each response by RCODE +
// shape (positive answer, negative answer, error), looks up a bucket
// keyed on (source-prefix, response-name, class), and either lets the
// response through, drops it, or sends a TC=1 truncated stub
// according to the slip rate.
//
// Composing with [NewRateLimit]: NewRateLimit caps queries per
// source; NewRRL caps responses by content. Using both together gives
// a layered defence (per-host throttling for noisy clients, per-name
// throttling for amplification targets). NewRRL alone is sufficient
// against amplification; NewRateLimit alone is not, because spoofed
// sources defeat per-source query budgets.
func NewRRL(inner Handler, opts ...RRLOption) Handler {
	c := rrlConfig{
		respPerSecond:   10,
		nxdomainsPerS:   5,
		errorsPerSecond: 5,
		slip:            2,
		v4Prefix:        24,
		v6Prefix:        56,
		maxKeys:         100000,
	}
	for _, o := range opts {
		o.applyRRL(&c)
	}
	if c.burst == 0 {
		// Default burst tracks the largest of the per-class rates so a
		// fresh bucket always permits at least one immediate response.
		largest := c.respPerSecond
		if c.nxdomainsPerS > largest {
			largest = c.nxdomainsPerS
		}
		if c.errorsPerSecond > largest {
			largest = c.errorsPerSecond
		}
		if largest <= 0 {
			largest = 1
		}
		c.burst = int(2 * largest)
	}
	return &rrl{
		inner:           inner,
		respPerSecond:   c.respPerSecond,
		nxdomainsPerS:   c.nxdomainsPerS,
		errorsPerSecond: c.errorsPerSecond,
		burst:           float64(c.burst),
		slip:            c.slip,
		v4Prefix:        c.v4Prefix,
		v6Prefix:        c.v6Prefix,
		maxKeys:         c.maxKeys,
		buckets:         make(map[string]*rrlBucket),
	}
}

func (r *rrl) ServeDNS(ctx context.Context, w ResponseWriter, q wire.Message) {
	gw := &rrlWriter{ResponseWriter: w, parent: r, q: q}
	r.inner.ServeDNS(ctx, gw, q)
}

// rrlWriter intercepts the inner handler's WriteMsg, classifies the
// response, and decides whether to forward, drop, or truncate.
type rrlWriter struct {
	ResponseWriter

	parent *rrl
	q      wire.Message
	wrote  bool
}

func (g *rrlWriter) WriteMsg(m wire.Message) error {
	if g.wrote {
		return g.ResponseWriter.WriteMsg(m)
	}
	g.wrote = true

	rate := g.parent.rateFor(m)
	if rate <= 0 {
		// Class disabled (rate 0): treat as unrestricted.
		return g.ResponseWriter.WriteMsg(m)
	}

	src := g.ResponseWriter.RemoteAddr().Addr()
	respName := responseKeyName(m, g.q)
	key := g.parent.bucketKey(src, respName, classify(m))

	allowed, slip := g.parent.consume(key, rate)
	if allowed {
		return g.ResponseWriter.WriteMsg(m)
	}
	if slip {
		return g.ResponseWriter.WriteMsg(truncateForRRL(m, g.q))
	}
	// Silent drop.
	return nil
}

// rateFor returns the per-second token rate appropriate to the
// response's classification. A returned 0 means the class is exempt
// from rate-limiting (caller passes the response through unchanged).
func (r *rrl) rateFor(m wire.Message) float64 {
	switch classify(m) {
	case rrlClassPositive:
		return r.respPerSecond
	case rrlClassNegative:
		return r.nxdomainsPerS
	case rrlClassError:
		return r.errorsPerSecond
	}
	return 0
}

type rrlClass int

const (
	rrlClassUnknown rrlClass = iota
	rrlClassPositive
	rrlClassNegative
	rrlClassError
)

func classify(m wire.Message) rrlClass {
	rcode := m.Flags().RCODE()
	switch rcode {
	case wire.RCODENoError:
		if len(m.Answers()) > 0 {
			return rrlClassPositive
		}
		// NoData / referral — both look the same to RRL.
		return rrlClassNegative
	case wire.RCODENXDomain:
		return rrlClassNegative
	}
	return rrlClassError
}

func (r *rrl) bucketKey(src netip.Addr, name wire.Name, class rrlClass) string {
	var prefixedAddr netip.Addr
	if src.Is4() {
		if pfx, err := src.Prefix(r.v4Prefix); err == nil {
			prefixedAddr = pfx.Addr()
		} else {
			prefixedAddr = src
		}
	} else {
		if pfx, err := src.Prefix(r.v6Prefix); err == nil {
			prefixedAddr = pfx.Addr()
		} else {
			prefixedAddr = src
		}
	}
	return prefixedAddr.String() + "|" + name.String() + "|" + classString(class)
}

func classString(c rrlClass) string {
	switch c {
	case rrlClassPositive:
		return "+"
	case rrlClassNegative:
		return "-"
	case rrlClassError:
		return "!"
	}
	return "?"
}

// consume debits the bucket. Returns (allowed, slip). When allowed is
// false, slip indicates whether this blocked response should be
// converted into a TC=1 truncated reply (true) or silently dropped
// (false). Slip alternates per bucket every slipRate blocked
// responses; e.g. slip=2 means every other blocked response is
// slipped through as a truncated answer.
func (r *rrl) consume(key string, rate float64) (bool, bool) {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.buckets[key]
	if !ok {
		if r.maxKeys > 0 && len(r.buckets) >= r.maxKeys {
			r.evictLocked(now)
		}
		b = &rrlBucket{tokens: r.burst, updated: now}
		r.buckets[key] = b
	}
	elapsed := now.Sub(b.updated).Seconds()
	b.tokens += elapsed * rate
	if b.tokens > r.burst {
		b.tokens = r.burst
	}
	b.updated = now
	if b.tokens >= 1 {
		b.tokens--
		return true, false
	}
	// Over budget. Decide slip vs drop.
	if r.slip <= 0 {
		return false, false
	}
	b.slipCounter++
	if b.slipCounter >= r.slip {
		b.slipCounter = 0
		return false, true
	}
	return false, false
}

// evictLocked drops idle (refilled) buckets first; if still at the cap,
// drops the oldest-updated entry. Caller holds r.mu.
func (r *rrl) evictLocked(now time.Time) {
	largestRate := r.respPerSecond
	if r.nxdomainsPerS > largestRate {
		largestRate = r.nxdomainsPerS
	}
	if r.errorsPerSecond > largestRate {
		largestRate = r.errorsPerSecond
	}
	if largestRate > 0 {
		idleFor := time.Duration(r.burst/largestRate*float64(time.Second)) + time.Second
		threshold := now.Add(-idleFor)
		for k, b := range r.buckets {
			if b.updated.Before(threshold) {
				delete(r.buckets, k)
			}
		}
	}
	if r.maxKeys <= 0 || len(r.buckets) < r.maxKeys {
		return
	}
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, b := range r.buckets {
		if first || b.updated.Before(oldestTime) {
			oldestKey = k
			oldestTime = b.updated
			first = false
		}
	}
	delete(r.buckets, oldestKey)
}

// responseKeyName is the canonical name to bucket a response by. We
// prefer the name the client asked about (q.Questions()[0].Name())
// over the first answer owner so referrals and CNAME-target answers
// still bucket against the original qname — otherwise an attacker can
// rotate the chase target to evade the limiter.
func responseKeyName(m wire.Message, q wire.Message) wire.Name {
	if qs := q.Questions(); len(qs) > 0 {
		return qs[0].Name()
	}
	if ms := m.Questions(); len(ms) > 0 {
		return ms[0].Name()
	}
	return wire.Name{}
}

// truncateForRRL builds a slip reply: copies ID, opcode, RD echo,
// question, and OPT (if any) from the original response, sets TC=1.
// The client will retry over TCP, where RRL doesn't apply.
func truncateForRRL(m wire.Message, q wire.Message) wire.Message {
	b := wire.NewBuilder().
		ID(m.ID()).
		Flags(m.Flags().WithTruncated(true).WithResponse(true))
	if qs := m.Questions(); len(qs) > 0 {
		b = b.Question(qs[0])
	} else if qs := q.Questions(); len(qs) > 0 {
		b = b.Question(qs[0])
	}
	if e, ok := m.EDNS(); ok && e != nil {
		b = b.EDNS(e)
	}
	out, err := b.Build()
	if err != nil {
		return m // fall back to original on builder error
	}
	return out
}
