// Package dnsclient is the user-facing entry point for performing DNS
// queries against a configured resolver.
//
// Two layers are exposed: the low-level transport.Exchanger (one query, one
// response, no retry, no fall-back) and the high-level Resolver, which adds
// query construction, ID randomisation, parallel A/AAAA dispatch, and typed
// convenience helpers.
package dnsclient

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient/resolvconf"
	"github.com/lestrrat-go/acidns/dnsclient/specialuse"
	"github.com/lestrrat-go/acidns/dnsclient/transport"
	"github.com/lestrrat-go/acidns/dnsclient/transport/tcp"
	"github.com/lestrrat-go/acidns/dnsclient/transport/udp"
	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
)

// ErrNoResolver is returned when New cannot construct a Resolver because no
// transport or server list was provided.
var ErrNoResolver = errors.New("dnsclient: no exchanger or servers configured")

// Resolver performs DNS queries on behalf of an application. Resolve is the
// single primitive — typed convenience helpers (LookupHost, ResolveAs[T],
// Extract[T], ...) live as package-level functions that wrap a Resolver.
//
// Implementations are free to satisfy additional capability interfaces such
// as SearchLister; helpers type-assert for those capabilities and fall back
// gracefully when they are absent.
type Resolver interface {
	// Resolve performs a single query and returns the matched records along
	// with the raw response. A non-NoError RCODE is returned as a typed
	// *RCodeError carrying the response; the matched record list is empty
	// in that case.
	Resolve(ctx context.Context, name dnsname.Name, t rrtype.Type) (Answer, error)
}

// SearchLister is an optional capability satisfied by resolver impls that
// know about a search list and an ndots threshold. Helpers like LookupHost
// type-assert against this to expand short names; resolvers without this
// capability skip the expansion step.
type SearchLister interface {
	SearchList() []dnsname.Name
	Ndots() int
}

// Answer is the typed result of a Resolve call.
type Answer interface {
	Question() dnsmsg.Question
	Records() []dnsmsg.Record
	Raw() dnsmsg.Message
	RCODE() dnsmsg.RCODE
	Authoritative() bool
	Truncated() bool
}

type answer struct {
	q       dnsmsg.Question
	records []dnsmsg.Record
	raw     dnsmsg.Message
}

func (a *answer) Question() dnsmsg.Question { return a.q }
func (a *answer) Records() []dnsmsg.Record  { return a.records }
func (a *answer) Raw() dnsmsg.Message       { return a.raw }
func (a *answer) RCODE() dnsmsg.RCODE       { return a.raw.Flags().RCODE() }
func (a *answer) Authoritative() bool       { return a.raw.Flags().Authoritative() }
func (a *answer) Truncated() bool           { return a.raw.Flags().Truncated() }

// Option configures a Resolver.
type Option interface{ applyResolver(*config) }

type optionFunc func(*config)

func (f optionFunc) applyResolver(c *config) { f(c) }

type config struct {
	exchanger        transport.Exchanger
	servers          []netip.AddrPort
	ednsUDP          uint16
	ednsDO           bool
	disableEDNS      bool
	attempts         int
	perAttempt       time.Duration
	searchList       []dnsname.Name
	ndots            int
	ndotsSet         bool
	disableSpecialUse bool
	systemErr        error
}

// WithExchanger pins the Resolver to a specific transport. Mutually
// exclusive with WithServers.
func WithExchanger(ex transport.Exchanger) Option {
	return optionFunc(func(c *config) { c.exchanger = ex })
}

// WithServers configures the Resolver to talk UDP to the given servers in
// order, falling over to the next on failure.
func WithServers(servers ...netip.AddrPort) Option {
	return optionFunc(func(c *config) { c.servers = append(c.servers[:0], servers...) })
}

// WithEDNSUDPSize advertises a non-default UDP payload size in OPT.
// The default (1232) follows IETF DNS Flag Day 2020.
func WithEDNSUDPSize(n uint16) Option {
	return optionFunc(func(c *config) { c.ednsUDP = n })
}

// WithDNSSEC toggles the DO bit in OPT. When true (default false), DNSSEC
// RRs are requested in responses.
func WithDNSSEC(v bool) Option {
	return optionFunc(func(c *config) { c.ednsDO = v })
}

// WithEDNS toggles inclusion of the OPT pseudo-RR in outgoing queries.
// Default is true — pass false only when targeting servers known to
// misbehave on EDNS.
func WithEDNS(v bool) Option {
	return optionFunc(func(c *config) { c.disableEDNS = !v })
}

// WithAttempts sets how many times each server is retried before failover
// to the next. Defaults to 1 (no retry). Applied only to WithServers; a
// caller-supplied WithExchanger handles its own retry policy.
func WithAttempts(n int) Option {
	return optionFunc(func(c *config) { c.attempts = n })
}

// WithPerAttemptTimeout caps the duration of each attempt. Zero means the
// outer context's deadline (if any) is the only bound.
func WithPerAttemptTimeout(d time.Duration) Option {
	return optionFunc(func(c *config) { c.perAttempt = d })
}

// WithSystemResolvers loads /etc/resolv.conf and uses its nameservers,
// search list, and ndots, equivalent to WithServers + WithSearchList +
// WithNdots sourced from the system file. Returns an error from New if no
// nameserver entries are found.
func WithSystemResolvers() Option {
	return optionFunc(func(c *config) {
		cfg, err := resolvconf.Load("")
		if err != nil {
			c.systemErr = err
			return
		}
		if len(cfg.Nameservers) == 0 {
			c.systemErr = resolvconf.ErrNoNameserver
			return
		}
		c.servers = append(c.servers[:0], cfg.Nameservers...)
		c.searchList = append(c.searchList[:0], cfg.Search...)
		c.ndots = cfg.Ndots
		c.ndotsSet = true
	})
}

// WithSpecialUse toggles the RFC 6761 short-circuits applied to names like
// localhost., *.invalid., and *.onion. Default is true — pass false for
// tooling that needs to interrogate a DNS server about how it handles those
// names rather than having the resolver answer locally.
func WithSpecialUse(v bool) Option {
	return optionFunc(func(c *config) { c.disableSpecialUse = !v })
}

// WithSearchList sets the suffixes appended to short names by LookupHost.
// Names with a trailing dot bypass the search list.
func WithSearchList(suffixes ...dnsname.Name) Option {
	return optionFunc(func(c *config) { c.searchList = append(c.searchList[:0], suffixes...) })
}

// WithNdots sets the threshold of dots above which a name is tried in
// absolute form before applying the search list. Defaults to 1.
func WithNdots(n int) Option {
	return optionFunc(func(c *config) { c.ndots = n; c.ndotsSet = true })
}

type resolver struct {
	exchanger         transport.Exchanger
	ednsUDP           uint16
	ednsDO            bool
	disableEDNS       bool
	searchList        []dnsname.Name
	ndots             int
	disableSpecialUse bool
}

// New returns a Resolver. Exactly one of WithExchanger or WithServers must
// be supplied.
func New(opts ...Option) (Resolver, error) {
	c := config{ednsUDP: 1232}
	for _, o := range opts {
		o.applyResolver(&c)
	}
	if c.systemErr != nil {
		return nil, c.systemErr
	}
	if c.exchanger == nil && len(c.servers) == 0 {
		return nil, ErrNoResolver
	}
	if c.exchanger != nil && len(c.servers) > 0 {
		return nil, fmt.Errorf("dnsclient: WithExchanger and WithServers are mutually exclusive")
	}

	ex := c.exchanger
	if ex == nil {
		built, err := buildFallover(c.servers, c.attempts, c.perAttempt)
		if err != nil {
			return nil, err
		}
		ex = built
	}
	ndots := 1
	if c.ndotsSet {
		ndots = c.ndots
	}
	return &resolver{
		exchanger:         ex,
		ednsUDP:           c.ednsUDP,
		ednsDO:            c.ednsDO,
		disableEDNS:       c.disableEDNS,
		searchList:        append([]dnsname.Name(nil), c.searchList...),
		ndots:             ndots,
		disableSpecialUse: c.disableSpecialUse,
	}, nil
}

func (r *resolver) Resolve(ctx context.Context, name dnsname.Name, t rrtype.Type) (Answer, error) {
	if !r.disableSpecialUse {
		if ans, ok := r.specialUseAnswer(name, t); ok {
			return wrapRCode(ans)
		}
	}
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	b := dnsmsg.NewBuilder().
		ID(id).
		RecursionDesired(true).
		Question(dnsmsg.NewQuestion(name, t))
	if !r.disableEDNS {
		b = b.EDNS(dnsmsg.NewEDNSBuilder().
			UDPSize(r.ednsUDP).
			DO(r.ednsDO).
			Build())
	}
	q, err := b.Build()
	if err != nil {
		return nil, err
	}
	resp, err := r.exchanger.Exchange(ctx, q)
	if err != nil {
		return nil, err
	}
	q0 := resp.Questions()
	var question dnsmsg.Question
	if len(q0) > 0 {
		question = q0[0]
	}

	matched := matchAnswers(resp.Answers(), name, t)
	return wrapRCode(&answer{q: question, records: matched, raw: resp})
}

// wrapRCode converts an Answer with a non-NoError RCODE into an RCodeError
// carrying that answer. NoError responses are returned (Answer, nil).
func wrapRCode(ans Answer) (Answer, error) {
	if rcode := ans.RCODE(); rcode != dnsmsg.RCODENoError {
		return nil, &RCodeError{Code: rcode, Answer: ans}
	}
	return ans, nil
}

// specialUseAnswer applies the RFC 6761 short-circuit. It returns
// (answer, true) when the resolver should NOT issue a network query.
func (r *resolver) specialUseAnswer(name dnsname.Name, t rrtype.Type) (Answer, bool) {
	switch specialuse.For(name) {
	case specialuse.SynthLocalhost:
		records := make([]dnsmsg.Record, 0, 1)
		for _, addr := range specialuse.LoopbackForType(t) {
			var rd rdata.RData
			switch t {
			case rrtype.A:
				rd = rdata.NewA(addr)
			case rrtype.AAAA:
				rd = rdata.NewAAAA(addr)
			}
			if rd != nil {
				records = append(records,
					dnsmsg.NewRecord(name, 0, rd))
			}
		}
		raw := synthMessage(name, t, records, dnsmsg.RCODENoError)
		return &answer{q: dnsmsg.NewQuestion(name, t), records: records, raw: raw}, true
	case specialuse.Refuse, specialuse.Local:
		raw := synthMessage(name, t, nil, dnsmsg.RCODENXDomain)
		return &answer{q: dnsmsg.NewQuestion(name, t), raw: raw}, true
	default:
		return nil, false
	}
}

func synthMessage(name dnsname.Name, t rrtype.Type, records []dnsmsg.Record, rcode dnsmsg.RCODE) dnsmsg.Message {
	b := dnsmsg.NewBuilder().
		ID(0).
		Response(true).
		RecursionDesired(true).
		RecursionAvailable(true).
		Question(dnsmsg.NewQuestion(name, t))
	if rcode != dnsmsg.RCODENoError {
		b = b.RCODE(rcode)
	}
	for _, rec := range records {
		b = b.Answer(rec)
	}
	m, _ := b.Build()
	return m
}

// matchAnswers walks any CNAME chain starting at qname, then collects every
// answer record of qtype whose owner is the final target. CNAMEs in the
// chain are NOT included — Records() is the typed result, the raw
// response (including CNAMEs) remains accessible via Answer.Raw().
func matchAnswers(answers []dnsmsg.Record, qname dnsname.Name, qtype rrtype.Type) []dnsmsg.Record {
	const maxHops = 8
	target := qname
	if qtype != rrtype.CNAME {
		for hop := 0; hop < maxHops; hop++ {
			var next dnsname.Name
			found := false
			for _, rec := range answers {
				if rec.Type() != rrtype.CNAME || !rec.Name().Equal(target) {
					continue
				}
				next = rec.RData().(rdata.CNAME).Target()
				found = true
				break
			}
			if !found {
				break
			}
			target = next
		}
	}
	out := make([]dnsmsg.Record, 0, len(answers))
	for _, rec := range answers {
		if rec.Type() == qtype && rec.Name().Equal(target) {
			out = append(out, rec)
		}
	}
	return out
}

// SearchList satisfies SearchLister so package-level helpers (LookupHost,
// future search-list-aware lookups) can expand short names against the
// resolver's configured suffixes.
func (r *resolver) SearchList() []dnsname.Name { return r.searchList }

// Ndots satisfies SearchLister.
func (r *resolver) Ndots() int { return r.ndots }

func randomID() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("dnsclient: random id: %w", err)
	}
	return binary.BigEndian.Uint16(b[:]), nil
}

func buildFallover(servers []netip.AddrPort, attempts int, perAttempt time.Duration) (transport.Exchanger, error) {
	exs := make([]transport.Exchanger, 0, len(servers))
	for _, s := range servers {
		uex, err := udp.New(s)
		if err != nil {
			return nil, err
		}
		tex, err := tcp.New(s)
		if err != nil {
			return nil, err
		}
		var ex transport.Exchanger = &tcFallback{primary: uex, fallback: tex}
		if attempts > 1 || perAttempt > 0 {
			ex = &retryExchanger{inner: ex, attempts: max(attempts, 1), perAttempt: perAttempt}
		}
		exs = append(exs, ex)
	}
	if len(exs) == 1 {
		return exs[0], nil
	}
	return &failover{exs: exs}, nil
}

// retryExchanger retries a wrapped Exchanger up to attempts times, with an
// optional per-attempt timeout that caps each individual try.
type retryExchanger struct {
	inner      transport.Exchanger
	attempts   int
	perAttempt time.Duration
}

func (r *retryExchanger) Exchange(ctx context.Context, q dnsmsg.Message) (dnsmsg.Message, error) {
	var lastErr error
	for i := 0; i < r.attempts; i++ {
		attemptCtx := ctx
		var cancel context.CancelFunc
		if r.perAttempt > 0 {
			attemptCtx, cancel = context.WithTimeout(ctx, r.perAttempt)
		}
		resp, err := r.inner.Exchange(attemptCtx, q)
		if cancel != nil {
			cancel()
		}
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, lastErr
}

type failover struct{ exs []transport.Exchanger }

func (f *failover) Exchange(ctx context.Context, q dnsmsg.Message) (dnsmsg.Message, error) {
	var lastErr error
	for _, ex := range f.exs {
		resp, err := ex.Exchange(ctx, q)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, lastErr
}

// tcFallback wraps a primary (typically UDP) exchanger with a fallback
// (typically TCP) for retrying truncated responses per RFC 1035 §4.2.1.
type tcFallback struct {
	primary, fallback transport.Exchanger
}

func (e *tcFallback) Exchange(ctx context.Context, q dnsmsg.Message) (dnsmsg.Message, error) {
	resp, err := e.primary.Exchange(ctx, q)
	if err != nil {
		return nil, err
	}
	if resp.Flags().Truncated() && e.fallback != nil {
		return e.fallback.Exchange(ctx, q)
	}
	return resp, nil
}
