// Package acidns is the user-facing entry point for performing DNS
// queries against a configured resolver.
//
// Two layers are exposed: the low-level Exchanger (one query, one
// response, no retry, no fall-back) and the high-level Resolver, which adds
// query construction, ID randomisation, parallel A/AAAA dispatch, and typed
// convenience helpers.
package acidns

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/lestrrat-go/acidns/resolvconf"
	"github.com/lestrrat-go/acidns/specialuse"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// ErrNoResolver is returned when New cannot construct a Resolver because no
// transport or server list was provided.
var ErrNoResolver = errors.New("acidns: no exchanger or servers configured")

// Resolver performs DNS queries on behalf of an application. Resolve is the
// single primitive — typed convenience helpers (LookupHost, ResolveAs[T],
// Extract[T], ...) live as package-level functions that wrap a Resolver.
//
// Implementations are free to satisfy additional capability interfaces such
// as SearchLister; helpers type-assert for those capabilities and fall back
// gracefully when they are absent.
//
// Resolver implementations MUST be safe for concurrent use by multiple
// goroutines. The resolver returned by NewResolver and SystemResolver
// satisfies this contract.
type Resolver interface {
	// Resolve performs a single query and returns the matched records along
	// with the raw response. A non-NoError RCODE is returned as a typed
	// *RCodeError carrying the response; the matched record list is empty
	// in that case.
	Resolve(ctx context.Context, name wire.Name, t rrtype.Type) (*Answer, error)
}

// SearchLister is an optional capability satisfied by resolver impls that
// know about a search list and an ndots threshold. Helpers like LookupHost
// type-assert against this to expand short names; resolvers without this
// capability skip the expansion step.
type SearchLister interface {
	SearchList() []wire.Name
	Ndots() int
}

// Answer is the typed result of a Resolve call.
type Answer struct {
	q       wire.Question
	records []wire.Record
	raw     wire.Message
}

// NewAnswer wraps a question, the matched records, and the raw response into
// an Answer. Intended for resolver implementations and test fakes that need
// to synthesise an Answer outside the package.
func NewAnswer(q wire.Question, records []wire.Record, raw wire.Message) *Answer {
	return &Answer{q: q, records: records, raw: raw}
}

func (a *Answer) Question() wire.Question { return a.q }
func (a *Answer) Records() []wire.Record  { return a.records }
func (a *Answer) Raw() wire.Message       { return a.raw }
func (a *Answer) RCODE() wire.RCODE       { return a.raw.Flags().RCODE() }
func (a *Answer) Authoritative() bool     { return a.raw.Flags().Authoritative() }
func (a *Answer) Truncated() bool         { return a.raw.Flags().Truncated() }

// ResolverOption configures a Resolver.
type ResolverOption interface{ applyResolver(*resolverConfig) }

type resolverOptionFunc func(*resolverConfig)

func (f resolverOptionFunc) applyResolver(c *resolverConfig) { f(c) }

type resolverConfig struct {
	exchanger         Exchanger
	servers           []netip.AddrPort
	ednsUDP           uint16
	ednsDO            bool
	disableEDNS       bool
	attempts          int
	perAttempt        time.Duration
	searchList        []wire.Name
	ndots             int
	ndotsSet          bool
	disableSpecialUse bool
	disable0x20       bool
	logger            *slog.Logger
	systemErr         error
}

// WithExchanger pins the Resolver to a specific transport. Mutually
// exclusive with WithServers.
func WithExchanger(ex Exchanger) ResolverOption {
	return resolverOptionFunc(func(c *resolverConfig) { c.exchanger = ex })
}

// WithServers configures the Resolver to talk UDP to the given servers in
// order, falling over to the next on failure.
func WithServers(servers ...netip.AddrPort) ResolverOption {
	return resolverOptionFunc(func(c *resolverConfig) { c.servers = append(c.servers[:0], servers...) })
}

// WithEDNSUDPSize advertises a non-default UDP payload size in OPT.
// The default (1232) follows IETF DNS Flag Day 2020.
func WithEDNSUDPSize(n uint16) ResolverOption {
	return resolverOptionFunc(func(c *resolverConfig) { c.ednsUDP = n })
}

// WithDNSSEC toggles the DO bit in OPT. When true (default false), DNSSEC
// RRs are requested in responses.
func WithDNSSEC(v bool) ResolverOption {
	return resolverOptionFunc(func(c *resolverConfig) { c.ednsDO = v })
}

// WithEDNS toggles inclusion of the OPT pseudo-RR in outgoing queries.
// Default is true — pass false only when targeting servers known to
// misbehave on EDNS.
func WithEDNS(v bool) ResolverOption {
	return resolverOptionFunc(func(c *resolverConfig) { c.disableEDNS = !v })
}

// WithAttempts sets how many times each server is retried before failover
// to the next. Defaults to 1 (no retry). Applied only to WithServers; a
// caller-supplied WithExchanger handles its own retry policy.
func WithAttempts(n int) ResolverOption {
	return resolverOptionFunc(func(c *resolverConfig) { c.attempts = n })
}

// WithPerAttemptTimeout caps the duration of each attempt. Zero means the
// outer context's deadline (if any) is the only bound.
func WithPerAttemptTimeout(d time.Duration) ResolverOption {
	return resolverOptionFunc(func(c *resolverConfig) { c.perAttempt = d })
}

// WithSystemResolvers loads /etc/resolv.conf and uses its nameservers,
// search list, and ndots, equivalent to WithServers + WithSearchList +
// WithNdots sourced from the system file. Returns an error from New if no
// nameserver entries are found.
func WithSystemResolvers() ResolverOption {
	return resolverOptionFunc(func(c *resolverConfig) {
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

// WithCaseRandomization toggles RFC 5452 §9.3 0x20 hardening on the
// UDP exchangers built from [WithServers]. Default is true: 0x20
// materially raises the off-path spoofing search space at no
// operational cost against modern authoritatives. Pass false only
// when targeting an upstream known to silently lowercase the qname
// in responses.
//
// The option has no effect when [WithExchanger] is supplied — a
// caller-built Exchanger applies whatever 0x20 policy its own
// constructor was given.
func WithCaseRandomization(v bool) ResolverOption {
	return resolverOptionFunc(func(c *resolverConfig) { c.disable0x20 = !v })
}

// WithSpecialUse toggles the RFC 6761 short-circuits applied to names like
// localhost., *.invalid., and *.onion. Default is true — pass false for
// tooling that needs to interrogate a DNS server about how it handles those
// names rather than having the resolver answer locally.
func WithSpecialUse(v bool) ResolverOption {
	return resolverOptionFunc(func(c *resolverConfig) { c.disableSpecialUse = !v })
}

// WithSearchList sets the suffixes appended to short names by LookupHost.
// Names with a trailing dot bypass the search list.
func WithSearchList(suffixes ...wire.Name) ResolverOption {
	return resolverOptionFunc(func(c *resolverConfig) { c.searchList = append(c.searchList[:0], suffixes...) })
}

// WithNdots sets the threshold of dots above which a name is tried in
// absolute form before applying the search list. Defaults to 1.
func WithNdots(n int) ResolverOption {
	return resolverOptionFunc(func(c *resolverConfig) { c.ndots = n; c.ndotsSet = true })
}

// WithLogger attaches a slog.Logger that the Resolver uses to emit
// structured tracepoints around each Resolve call: "resolver.resolve" at
// debug level on success (with name, type, elapsed, rcode) and at error
// level when the upstream returns an error or non-NoError RCODE.
//
// The default is a no-op handler — passing nil restores the default.
func WithLogger(l *slog.Logger) ResolverOption {
	return resolverOptionFunc(func(c *resolverConfig) { c.logger = l })
}

type resolver struct {
	exchanger         Exchanger
	ednsUDP           uint16
	ednsDO            bool
	disableEDNS       bool
	searchList        []wire.Name
	ndots             int
	disableSpecialUse bool
	logger            *slog.Logger
}

// NewResolver returns a Resolver. Exactly one of WithExchanger or WithServers
// must be supplied.
func NewResolver(opts ...ResolverOption) (Resolver, error) {
	c := resolverConfig{ednsUDP: 1232}
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
		return nil, fmt.Errorf("acidns: WithExchanger and WithServers are mutually exclusive")
	}

	ex := c.exchanger
	if ex == nil {
		built, err := buildFallover(c.servers, c.attempts, c.perAttempt, !c.disable0x20)
		if err != nil {
			return nil, err
		}
		ex = built
	}
	ndots := 1
	if c.ndotsSet {
		ndots = c.ndots
	}
	logger := c.logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &resolver{
		exchanger:         ex,
		ednsUDP:           c.ednsUDP,
		ednsDO:            c.ednsDO,
		disableEDNS:       c.disableEDNS,
		searchList:        append([]wire.Name(nil), c.searchList...),
		ndots:             ndots,
		disableSpecialUse: c.disableSpecialUse,
		logger:            logger,
	}, nil
}

// SystemResolver is the zero-config entry point: it loads /etc/resolv.conf
// for nameservers, search list, and ndots, and returns a ready-to-use
// Resolver. Additional options are applied after WithSystemResolvers and
// can override any field (e.g. WithExchanger to replace the default UDP
// transport with DoT/DoH/DoQ).
//
// It is the analogue of Go's net.DefaultResolver — fine for one-off
// programs, CLI tools, and tests. Long-running daemons that want explicit
// control should call NewResolver directly.
func SystemResolver(opts ...ResolverOption) (Resolver, error) {
	full := make([]ResolverOption, 0, len(opts)+1)
	full = append(full, WithSystemResolvers())
	full = append(full, opts...)
	return NewResolver(full...)
}

func (r *resolver) Resolve(ctx context.Context, name wire.Name, t rrtype.Type) (*Answer, error) {
	start := time.Now()
	ans, err := r.resolve(ctx, name, t)
	r.logResolve(ctx, name, t, ans, err, time.Since(start))
	return ans, err
}

func (r *resolver) resolve(ctx context.Context, name wire.Name, t rrtype.Type) (*Answer, error) {
	if !r.disableSpecialUse {
		if ans, ok := r.specialUseAnswer(name, t); ok {
			return wrapRCode(ans)
		}
	}
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	b := wire.NewBuilder().
		ID(id).
		RecursionDesired(true).
		Question(wire.NewQuestion(name, t))
	if !r.disableEDNS {
		ed, eerr := wire.NewEDNSBuilder().
			UDPSize(r.ednsUDP).
			DO(r.ednsDO).
			Build()
		if eerr != nil {
			return nil, eerr
		}
		b = b.EDNS(ed)
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
	var question wire.Question
	if len(q0) > 0 {
		question = q0[0]
	}

	matched := matchAnswers(resp.Answers(), name, t)
	return wrapRCode(&Answer{q: question, records: matched, raw: resp})
}

// logResolve emits one structured event per Resolve call. Successful
// NoError answers go to debug; errors and non-NoError RCODEs go to error
// level.
func (r *resolver) logResolve(ctx context.Context, name wire.Name, t rrtype.Type, ans *Answer, err error, elapsed time.Duration) {
	attrs := []slog.Attr{
		slog.String("name", name.String()),
		slog.String("type", t.String()),
		slog.Duration("elapsed", elapsed),
	}
	if err != nil {
		var rce *RCodeError
		if errors.As(err, &rce) {
			attrs = append(attrs, slog.String("rcode", rce.Code.String()))
			r.logger.LogAttrs(ctx, slog.LevelWarn, "resolver.resolve", attrs...)
			return
		}
		attrs = append(attrs, slog.String("error", err.Error()))
		r.logger.LogAttrs(ctx, slog.LevelError, "resolver.resolve", attrs...)
		return
	}
	if ans != nil {
		attrs = append(attrs, slog.Int("records", len(ans.Records())))
	}
	r.logger.LogAttrs(ctx, slog.LevelDebug, "resolver.resolve", attrs...)
}

// wrapRCode converts an Answer with a non-NoError RCODE into an RCodeError
// carrying that answer. NoError responses are returned (Answer, nil).
func wrapRCode(ans *Answer) (*Answer, error) {
	if rcode := ans.RCODE(); rcode != wire.RCODENoError {
		return nil, &RCodeError{Code: rcode, Answer: ans}
	}
	return ans, nil
}

// specialUseAnswer applies the RFC 6761 short-circuit. It returns
// (answer, true) when the resolver should NOT issue a network query.
func (r *resolver) specialUseAnswer(name wire.Name, t rrtype.Type) (*Answer, bool) {
	switch specialuse.For(name) {
	case specialuse.SynthLocalhost:
		records := make([]wire.Record, 0, 1)
		for _, addr := range specialuse.LoopbackForType(t) {
			var rd rdata.RData
			switch t {
			case rrtype.A:
				if a, err := rdata.NewA(addr); err == nil {
					rd = a
				}
			case rrtype.AAAA:
				if a, err := rdata.NewAAAA(addr); err == nil {
					rd = a
				}
			}
			if rd != nil {
				records = append(records,
					wire.NewRecord(name, 0, rd))
			}
		}
		raw := synthMessage(name, t, records, wire.RCODENoError)
		return &Answer{q: wire.NewQuestion(name, t), records: records, raw: raw}, true
	case specialuse.Refuse, specialuse.Local:
		raw := synthMessage(name, t, nil, wire.RCODENXDomain)
		return &Answer{q: wire.NewQuestion(name, t), raw: raw}, true
	default:
		return nil, false
	}
}

func synthMessage(name wire.Name, t rrtype.Type, records []wire.Record, rcode wire.RCODE) wire.Message {
	b := wire.NewBuilder().
		ID(0).
		Response(true).
		RecursionDesired(true).
		RecursionAvailable(true).
		Question(wire.NewQuestion(name, t))
	if rcode != wire.RCODENoError {
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
func matchAnswers(answers []wire.Record, qname wire.Name, qtype rrtype.Type) []wire.Record {
	const maxHops = 8
	target := qname
	if qtype != rrtype.CNAME {
		for range maxHops {
			var next wire.Name
			found := false
			for _, rec := range answers {
				if !rec.Name().Equal(target) {
					continue
				}
				cn, ok := wire.RDataAs[rdata.CNAME](rec)
				if !ok {
					continue
				}
				next = cn.Target()
				found = true
				break
			}
			if !found {
				break
			}
			target = next
		}
	}
	out := make([]wire.Record, 0, len(answers))
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
func (r *resolver) SearchList() []wire.Name { return slices.Clone(r.searchList) }

// Ndots satisfies SearchLister.
func (r *resolver) Ndots() int { return r.ndots }

func randomID() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("acidns: random id: %w", err)
	}
	return binary.BigEndian.Uint16(b[:]), nil
}

func buildFallover(servers []netip.AddrPort, attempts int, perAttempt time.Duration, use0x20 bool) (Exchanger, error) {
	exs := make([]Exchanger, 0, len(servers))
	for _, s := range servers {
		uex, err := NewUDPExchanger(s, WithUDP0x20(use0x20))
		if err != nil {
			return nil, err
		}
		tex, err := NewTCPExchanger(s)
		if err != nil {
			return nil, err
		}
		var ex Exchanger = &tcFallback{primary: uex, fallback: tex}
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
	inner      Exchanger
	attempts   int
	perAttempt time.Duration
}

func (r *retryExchanger) Exchange(ctx context.Context, q wire.Message) (wire.Message, error) {
	var lastErr error
	for i := range r.attempts {
		attempt := q
		// Mint a fresh transaction ID for every retry — RFC 5452 §10
		// expects each fired query to be an independent draw from the
		// 16-bit ID space so an off-path attacker observing one timeout
		// doesn't get N guesses at the same (id, qname) tuple.
		if i > 0 {
			id, err := randomID()
			if err != nil {
				return nil, err
			}
			attempt = wire.WithID(q, id)
		}
		attemptCtx := ctx
		var cancel context.CancelFunc
		if r.perAttempt > 0 {
			attemptCtx, cancel = context.WithTimeout(ctx, r.perAttempt)
		}
		resp, err := r.inner.Exchange(attemptCtx, attempt)
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

type failover struct{ exs []Exchanger }

func (f *failover) Exchange(ctx context.Context, q wire.Message) (wire.Message, error) {
	var lastErr error
	for i, ex := range f.exs {
		attempt := q
		if i > 0 {
			id, err := randomID()
			if err != nil {
				return nil, err
			}
			attempt = wire.WithID(q, id)
		}
		resp, err := ex.Exchange(ctx, attempt)
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
	primary, fallback Exchanger
}

func (e *tcFallback) Exchange(ctx context.Context, q wire.Message) (wire.Message, error) {
	resp, err := e.primary.Exchange(ctx, q)
	if err != nil {
		return nil, err
	}
	if resp.Flags().Truncated() && e.fallback != nil {
		return e.fallback.Exchange(ctx, q)
	}
	return resp, nil
}
