// Package recursive is a small iterative DNS resolver. It walks from the
// root servers downward, following NS referrals, optionally honouring glue
// records and recursively resolving NS targets when glue is absent.
//
// Out of scope for this version: DNSSEC validation, QNAME minimisation,
// pre-fetching, parallel server racing, EDNS-0 server cookies. The
// implementation is intentionally simple and synchronous so it can be
// audited and extended in clear steps.
package recursive

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/dnsserver"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// ErrIterationLimit is returned when the recursive resolver fails to reach
// an authoritative answer within the configured iteration cap.
var ErrIterationLimit = errors.New("recursive: iteration limit reached")

// Recursive is the public face of the resolver. It implements
// dnsserver.Handler so it can be plugged into ListenUDP / ListenTCP
// directly, and exposes Resolve for direct use from another handler or
// from tests.
type Recursive interface {
	dnsserver.Handler
	Resolve(ctx context.Context, name wire.Name, t rrtype.Type) (Entry, error)
}

// Option configures a Recursive at construction.
type Option interface{ applyRecursive(*config) }

type optionFunc func(*config)

func (f optionFunc) applyRecursive(c *config) { f(c) }

type config struct {
	roots         []netip.AddrPort
	cache         Cache
	maxIterations int
	maxDepth      int
	dialer        Dialer
}

// WithRoots overrides the default root server list.
func WithRoots(addrs ...netip.AddrPort) Option {
	return optionFunc(func(c *config) { c.roots = append(c.roots[:0], addrs...) })
}

// WithCache sets a custom Cache implementation.
func WithCache(c Cache) Option {
	return optionFunc(func(cfg *config) { cfg.cache = c })
}

// WithMaxIterations caps how many delegation steps a single query may
// traverse. Defaults to 30.
func WithMaxIterations(n int) Option {
	return optionFunc(func(c *config) { c.maxIterations = n })
}

// Dialer abstracts how the resolver delivers a query to a chosen server.
// The default Dialer uses UDP with TCP fall-back on TC=1; tests can inject
// a Dialer that rewrites addresses, applies network-namespacing, or
// captures traffic.
type Dialer interface {
	Exchange(ctx context.Context, server netip.AddrPort, q wire.Message) (wire.Message, error)
}

// WithDialer sets a custom Dialer.
func WithDialer(d Dialer) Option {
	return optionFunc(func(c *config) { c.dialer = d })
}

type recursive struct {
	roots         []netip.AddrPort
	cache         Cache
	maxIterations int
	maxDepth      int
	dialer        Dialer
}

// New returns a Recursive resolver.
func New(opts ...Option) Recursive {
	c := config{maxIterations: 30, maxDepth: 8}
	for _, o := range opts {
		o.applyRecursive(&c)
	}
	if c.cache == nil {
		c.cache = NewMemoryCache()
	}
	if c.dialer == nil {
		c.dialer = defaultDialer{}
	}
	return &recursive{
		roots:         append([]netip.AddrPort(nil), c.roots...),
		cache:         c.cache,
		maxIterations: c.maxIterations,
		maxDepth:      c.maxDepth,
		dialer:        c.dialer,
	}
}

// DefaultDialer returns the built-in Dialer (UDP with TCP fall-back on
// TC=1). Useful for tests that want to compose their own Dialer over the
// default behaviour.
func DefaultDialer() Dialer { return defaultDialer{} }

// defaultDialer dials UDP first and retries over TCP on TC=1.
type defaultDialer struct{}

func (defaultDialer) Exchange(ctx context.Context, server netip.AddrPort, q wire.Message) (wire.Message, error) {
	uex, err := acidns.NewUDPExchanger(server)
	if err != nil {
		return nil, err
	}
	resp, err := uex.Exchange(ctx, q)
	if err != nil {
		return nil, err
	}
	if resp.Flags().Truncated() {
		tex, terr := acidns.NewTCPExchanger(server)
		if terr != nil {
			return resp, nil
		}
		if r2, terr := tex.Exchange(ctx, q); terr == nil {
			return r2, nil
		}
	}
	return resp, nil
}

// ServeDNS implements dnsserver.Handler.
func (r *recursive) ServeDNS(ctx context.Context, w dnsserver.ResponseWriter, q wire.Message) {
	b := wire.NewBuilder().
		ID(q.ID()).
		Response(true).
		RecursionDesired(q.Flags().RecursionDesired()).
		RecursionAvailable(true)

	if len(q.Questions()) == 0 {
		_ = w.WriteMsg(must(b.RCODE(wire.RCODEFormErr).Build()))
		return
	}
	question := q.Questions()[0]
	b = b.Question(question)

	entry, err := r.Resolve(ctx, question.Name(), question.Type())
	if err != nil {
		_ = w.WriteMsg(must(b.RCODE(wire.RCODEServFail).Build()))
		return
	}
	for _, rec := range entry.Answer {
		b = b.Answer(rec)
	}
	for _, rec := range entry.Authority {
		b = b.Authority(rec)
	}
	for _, rec := range entry.Additional {
		b = b.Additional(rec)
	}
	if entry.RCODE != wire.RCODENoError {
		b = b.RCODE(entry.RCODE)
	}
	_ = w.WriteMsg(must(b.Build()))
}

func must(m wire.Message, err error) wire.Message {
	if err != nil {
		fb, _ := wire.NewBuilder().Response(true).RCODE(wire.RCODEServFail).Build()
		return fb
	}
	return m
}

// Resolve returns a cached or freshly-iterated entry for (name, t).
func (r *recursive) Resolve(ctx context.Context, name wire.Name, t rrtype.Type) (Entry, error) {
	return r.resolveDepth(ctx, name, t, 0)
}

func (r *recursive) resolveDepth(ctx context.Context, name wire.Name, t rrtype.Type, depth int) (Entry, error) {
	if depth >= r.maxDepth {
		return Entry{}, fmt.Errorf("recursive: depth limit reached for %s", name)
	}
	if e, ok := r.cache.Get(name, t); ok {
		return e, nil
	}

	servers := append([]netip.AddrPort(nil), r.roots...)
	for it := 0; it < r.maxIterations; it++ {
		if len(servers) == 0 {
			return Entry{}, fmt.Errorf("recursive: no servers to query for %s", name)
		}
		resp, err := r.queryAny(ctx, servers, name, t)
		if err != nil {
			return Entry{}, fmt.Errorf("recursive: query failed: %w", err)
		}

		// Authoritative answer or NXDOMAIN is terminal.
		if resp.Flags().Authoritative() {
			entry := entryFromResponse(resp)
			r.cache.Put(name, t, entry)
			return entry, nil
		}
		// Some servers don't set AA but still answer; if there are matching
		// records in the answer section, treat it as terminal.
		if hasAnswerFor(resp, name, t) {
			entry := entryFromResponse(resp)
			r.cache.Put(name, t, entry)
			return entry, nil
		}

		// Otherwise treat it as a referral.
		next, err := r.serversFromReferral(ctx, resp, depth)
		if err != nil {
			return Entry{}, err
		}
		if len(next) == 0 {
			return Entry{}, fmt.Errorf("recursive: empty referral for %s", name)
		}
		servers = next
	}
	return Entry{}, ErrIterationLimit
}

func (r *recursive) queryAny(ctx context.Context, servers []netip.AddrPort, name wire.Name, t rrtype.Type) (wire.Message, error) {
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	q, err := wire.NewBuilder().
		ID(id).
		// RD=0 — we are doing the recursion ourselves.
		Question(wire.NewQuestion(name, t)).
		EDNS(wire.NewEDNSBuilder().UDPSize(1232).Build()).
		Build()
	if err != nil {
		return nil, err
	}

	var lastErr error
	for _, s := range servers {
		resp, err := r.dialer.Exchange(ctx, s, q)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no servers")
	}
	return nil, lastErr
}

// serversFromReferral picks the addresses to query next. It prefers in-message
// glue (additional section) but falls back to recursively resolving the NS
// targets for out-of-bailiwick delegations.
func (r *recursive) serversFromReferral(ctx context.Context, resp wire.Message, depth int) ([]netip.AddrPort, error) {
	// First, try glue.
	var glued []netip.AddrPort
	var ungluedNS []wire.Name
	for _, auth := range resp.Authorities() {
		if auth.Type() != rrtype.NS {
			continue
		}
		target := auth.RData().(rdata.NS).NSDName()
		if addrs := glueFor(target, resp.Additionals()); len(addrs) > 0 {
			glued = append(glued, addrs...)
		} else {
			ungluedNS = append(ungluedNS, target)
		}
	}
	if len(glued) > 0 {
		return glued, nil
	}
	// No glue — resolve NS targets recursively. Bound by depth.
	var out []netip.AddrPort
	for _, ns := range ungluedNS {
		entry, err := r.resolveDepth(ctx, ns, rrtype.A, depth+1)
		if err != nil {
			continue
		}
		for _, rec := range entry.Answer {
			if rec.Type() == rrtype.A {
				out = append(out, netip.AddrPortFrom(rec.RData().(rdata.A).Addr(), 53))
			}
		}
	}
	return out, nil
}

func glueFor(target wire.Name, additional []wire.Record) []netip.AddrPort {
	var out []netip.AddrPort
	for _, add := range additional {
		if !add.Name().Equal(target) {
			continue
		}
		switch add.Type() {
		case rrtype.A:
			out = append(out, netip.AddrPortFrom(add.RData().(rdata.A).Addr(), 53))
		case rrtype.AAAA:
			out = append(out, netip.AddrPortFrom(add.RData().(rdata.AAAA).Addr(), 53))
		}
	}
	return out
}

func hasAnswerFor(resp wire.Message, name wire.Name, t rrtype.Type) bool {
	for _, rec := range resp.Answers() {
		if rec.Type() == t && rec.Name().Equal(name) {
			return true
		}
		if rec.Type() == rrtype.CNAME && rec.Name().Equal(name) {
			return true
		}
	}
	return false
}

func entryFromResponse(resp wire.Message) Entry {
	ttl := minTTL(60*time.Second, resp.Answers(), resp.Authorities())
	// RFC 2308 §5: negative responses (NXDOMAIN or NODATA — i.e. NOERROR
	// with no answers) are cached for at most the SOA MINIMUM field and the
	// SOA's own TTL, whichever is smaller. The SOA appears in the
	// authority section of the negative response.
	if len(resp.Answers()) == 0 {
		if neg := negativeCacheTTL(resp.Authorities()); neg > 0 && neg < ttl {
			ttl = neg
		}
	}
	return Entry{
		Answer:     append([]wire.Record(nil), resp.Answers()...),
		Authority:  append([]wire.Record(nil), resp.Authorities()...),
		Additional: append([]wire.Record(nil), resp.Additionals()...),
		RCODE:      resp.Flags().RCODE(),
		AA:         resp.Flags().Authoritative(),
		ExpiresAt:  time.Now().Add(ttl),
	}
}

// negativeCacheTTL implements RFC 2308 §5: returns the smaller of the SOA
// rdata's MINIMUM field and the SOA RR's TTL, or 0 if no SOA is present.
func negativeCacheTTL(authority []wire.Record) time.Duration {
	for _, r := range authority {
		if r.Type() != rrtype.SOA {
			continue
		}
		soa, ok := r.RData().(rdata.SOA)
		if !ok {
			continue
		}
		min := soa.Minimum()
		if r.TTL() < min {
			return r.TTL()
		}
		return min
	}
	return 0
}

func randomID() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}
