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
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient/resolvconf"
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

// Resolver performs DNS queries on behalf of an application. Each method
// returns typed results; the underlying wire-format response is also
// reachable via Answer.Raw for callers that need access to raw RDATA.
type Resolver interface {
	// Resolve performs a single recursive query and returns the matched
	// records along with the raw response.
	Resolve(ctx context.Context, name dnsname.Name, t rrtype.Type) (Answer, error)

	// LookupHost dispatches A and AAAA queries for host concurrently and
	// returns every address either query produced.
	LookupHost(ctx context.Context, host string) ([]netip.Addr, error)
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
	exchanger   transport.Exchanger
	servers     []netip.AddrPort
	ednsUDP     uint16
	ednsDO      bool
	disableEDNS bool
	attempts    int
	perAttempt  time.Duration
	searchList  []dnsname.Name
	ndots       int
	ndotsSet    bool
	systemErr   error
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

// WithDNSSECOK sets the DO bit in OPT, requesting DNSSEC RRs in responses.
func WithDNSSECOK(v bool) Option {
	return optionFunc(func(c *config) { c.ednsDO = v })
}

// WithoutEDNS disables OPT in outgoing queries. Use only when targeting
// servers known to misbehave on EDNS.
func WithoutEDNS() Option {
	return optionFunc(func(c *config) { c.disableEDNS = true })
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
	exchanger   transport.Exchanger
	ednsUDP     uint16
	ednsDO      bool
	disableEDNS bool
	searchList  []dnsname.Name
	ndots       int
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
		exchanger:   ex,
		ednsUDP:     c.ednsUDP,
		ednsDO:      c.ednsDO,
		disableEDNS: c.disableEDNS,
		searchList:  append([]dnsname.Name(nil), c.searchList...),
		ndots:       ndots,
	}, nil
}

func (r *resolver) Resolve(ctx context.Context, name dnsname.Name, t rrtype.Type) (Answer, error) {
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
	return &answer{q: question, records: matched, raw: resp}, nil
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

func (r *resolver) LookupHost(ctx context.Context, host string) ([]netip.Addr, error) {
	candidates, err := r.candidateNames(host)
	if err != nil {
		return nil, err
	}
	var firstErr error
	for _, name := range candidates {
		addrs, err := r.lookupHostAbsolute(ctx, name)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if len(addrs) > 0 {
			return addrs, nil
		}
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return nil, nil
}

// candidateNames builds the ordered list of FQDNs to attempt for a
// LookupHost call, applying the search list and ndots threshold.
func (r *resolver) candidateNames(host string) ([]dnsname.Name, error) {
	absolute := strings.HasSuffix(host, ".")
	base, err := dnsname.Parse(host)
	if err != nil {
		return nil, err
	}
	if absolute || len(r.searchList) == 0 {
		return []dnsname.Name{base}, nil
	}
	dots := strings.Count(strings.TrimSuffix(host, "."), ".")
	suffixed := make([]dnsname.Name, 0, len(r.searchList))
	for _, s := range r.searchList {
		full := host + "." + s.String()
		n, err := dnsname.Parse(full)
		if err != nil {
			continue
		}
		suffixed = append(suffixed, n)
	}
	if dots >= r.ndots {
		return append([]dnsname.Name{base}, suffixed...), nil
	}
	return append(suffixed, base), nil
}

func (r *resolver) lookupHostAbsolute(ctx context.Context, name dnsname.Name) ([]netip.Addr, error) {
	type result struct {
		addrs []netip.Addr
		err   error
	}
	ch := make(chan result, 2)
	var wg sync.WaitGroup
	wg.Add(2)

	dispatch := func(t rrtype.Type) {
		defer wg.Done()
		ans, err := r.Resolve(ctx, name, t)
		if err != nil {
			ch <- result{err: err}
			return
		}
		out := make([]netip.Addr, 0, len(ans.Records()))
		for _, rec := range ans.Records() {
			switch rec.Type() {
			case rrtype.A:
				out = append(out, rec.RData().(rdata.A).Addr())
			case rrtype.AAAA:
				out = append(out, rec.RData().(rdata.AAAA).Addr())
			}
		}
		ch <- result{addrs: out}
	}
	go dispatch(rrtype.A)
	go dispatch(rrtype.AAAA)
	wg.Wait()
	close(ch)

	var addrs []netip.Addr
	var firstErr error
	for r := range ch {
		if r.err != nil && firstErr == nil {
			firstErr = r.err
			continue
		}
		addrs = append(addrs, r.addrs...)
	}
	if len(addrs) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return addrs, nil
}

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
			ex = &retryExchanger{inner: ex, attempts: maxInt(attempts, 1), perAttempt: perAttempt}
		}
		exs = append(exs, ex)
	}
	if len(exs) == 1 {
		return exs[0], nil
	}
	return &fallover{exs: exs}, nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
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

type fallover struct{ exs []transport.Exchanger }

func (f *fallover) Exchange(ctx context.Context, q dnsmsg.Message) (dnsmsg.Message, error) {
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

// WrapWithTCFallback returns an Exchanger that sends queries through
// primary, and retries via fallback whenever the response has the TC bit
// set. Useful for composing custom transport stacks.
func WrapWithTCFallback(primary, fallback transport.Exchanger) transport.Exchanger {
	return &tcFallback{primary: primary, fallback: fallback}
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
