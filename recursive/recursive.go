// Package recursive is an iterative DNS resolver. It walks from the root
// servers downward, following NS referrals (with glue or out-of-bailiwick
// recursion), CNAME chains, and lame-server detection. Optional DNSSEC
// validation is delegated to dnssec/validator.
//
// Production features delivered:
//
//   - CNAME chain following with loop detection and depth cap.
//   - Lame delegation detection: REFUSED / SERVFAIL / no-answer servers are
//     marked failing and deprioritised.
//   - Per-server smoothed-RTT and failure-streak tracking; rankings prefer
//     fast and healthy upstreams.
//   - EDNS0 with TC=1 → TCP fall-back (DNS Flag Day 2020 buffer of 1232).
//   - Optional DNSSEC validation via WithValidator: bogus answers map to
//     SERVFAIL with EDE 6 (DNSSEC Bogus); insecure / indeterminate pass
//     through unchanged.
//   - RFC 2308 §5 negative caching with SOA MINIMUM cap.
//
// Deferred (TODO):
//
//   - QNAME minimisation (RFC 9156).
//   - Aggressive NSEC caching (RFC 8198).
//   - Parallel A/AAAA address resolution for NS targets.
//   - Per-upstream rate limiting and priming refresh.
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
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// ErrIterationLimit is returned when the resolver fails to reach an
// authoritative answer within the configured iteration cap.
var ErrIterationLimit = errors.New("recursive: iteration limit reached")

// ErrCNAMELoop is returned when a CNAME chain cycles or exceeds the depth
// cap.
var ErrCNAMELoop = errors.New("recursive: CNAME loop or chain too deep")

// ErrAllServersLame is returned when every candidate server returned an
// unusable response (REFUSED, SERVFAIL, or no progress).
var ErrAllServersLame = errors.New("recursive: all candidate servers lame")

// Recursive is the public face of the resolver. It implements
// acidns.Handler so it can be plugged into ListenUDP / ListenTCP directly,
// and exposes Resolve for direct use.
type Recursive interface {
	acidns.Handler
	Resolve(ctx context.Context, name wire.Name, t rrtype.Type) (Entry, error)
}

// Validator is the contract recursive expects from a DNSSEC validator.
// Any implementation that satisfies validator.Walker also satisfies this
// interface (acidns/dnssec/validator). The shape is structural so we avoid
// importing the validator package and creating an import cycle through the
// chain walker's Source path.
type Validator interface {
	Resolve(ctx context.Context, name wire.Name, t rrtype.Type) (ValidationResult, error)
}

// ValidationResult is what Validator.Resolve returns. It mirrors the
// validator.Answer shape so any validator package can satisfy it.
type ValidationResult interface {
	Result() ValidationStatus
	Records() []wire.Record
	RCODE() wire.RCODE
	Reason() error
}

// ValidationStatus enumerates the four outcomes of DNSSEC validation. The
// numeric values match validator.Result so the two types interoperate via
// type assertion in any package that imports both.
type ValidationStatus int

const (
	StatusSecure        ValidationStatus = 0
	StatusInsecure      ValidationStatus = 1
	StatusBogus         ValidationStatus = 2
	StatusIndeterminate ValidationStatus = 3
)

// Option configures a Recursive at construction.
type Option interface{ applyRecursive(*config) }

type optionFunc func(*config)

func (f optionFunc) applyRecursive(c *config) { f(c) }

type config struct {
	roots         []netip.AddrPort
	cache         Cache
	stats         ServerStats
	maxIterations int
	maxDepth      int
	maxCNAMEs     int
	dialer        Dialer
	validator     Validator
	queryTimeout  time.Duration
}

// WithRoots overrides the default root server list.
func WithRoots(addrs ...netip.AddrPort) Option {
	return optionFunc(func(c *config) { c.roots = append(c.roots[:0], addrs...) })
}

// WithCache sets a custom Cache implementation.
func WithCache(c Cache) Option {
	return optionFunc(func(cfg *config) { cfg.cache = c })
}

// WithServerStats sets a custom ServerStats implementation. The default is
// an in-memory store.
func WithServerStats(s ServerStats) Option {
	return optionFunc(func(c *config) { c.stats = s })
}

// WithMaxIterations caps how many delegation steps a single query may
// traverse. Defaults to 30.
func WithMaxIterations(n int) Option {
	return optionFunc(func(c *config) { c.maxIterations = n })
}

// WithMaxCNAMEDepth caps how many CNAME hops a single query may follow.
// Defaults to 8 — RFC 1035 doesn't specify a limit but every production
// resolver caps to defend against loops.
func WithMaxCNAMEDepth(n int) Option {
	return optionFunc(func(c *config) { c.maxCNAMEs = n })
}

// WithQueryTimeout sets a per-query timeout that bounds each individual
// upstream exchange (independent of any caller-supplied context). Defaults
// to 4 seconds.
func WithQueryTimeout(d time.Duration) Option {
	return optionFunc(func(c *config) { c.queryTimeout = d })
}

// WithValidator enables DNSSEC validation. The validator is invoked on
// every Resolve call; bogus answers become SERVFAIL responses bearing the
// configured EDE. The Resolver caches validated answers like any other.
func WithValidator(v Validator) Option {
	return optionFunc(func(c *config) { c.validator = v })
}

// Dialer abstracts how the resolver delivers a query to a chosen server.
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
	stats         ServerStats
	maxIterations int
	maxDepth      int
	maxCNAMEs     int
	dialer        Dialer
	validator     Validator
	queryTimeout  time.Duration
}

// New returns a Recursive resolver.
func New(opts ...Option) Recursive {
	c := config{
		maxIterations: 30,
		maxDepth:      8,
		maxCNAMEs:     8,
		queryTimeout:  4 * time.Second,
	}
	for _, o := range opts {
		o.applyRecursive(&c)
	}
	if c.cache == nil {
		c.cache = NewMemoryCache()
	}
	if c.stats == nil {
		c.stats = NewMemoryStats()
	}
	if c.dialer == nil {
		c.dialer = defaultDialer{}
	}
	return &recursive{
		roots:         append([]netip.AddrPort(nil), c.roots...),
		cache:         c.cache,
		stats:         c.stats,
		maxIterations: c.maxIterations,
		maxDepth:      c.maxDepth,
		maxCNAMEs:     c.maxCNAMEs,
		dialer:        c.dialer,
		validator:     c.validator,
		queryTimeout:  c.queryTimeout,
	}
}

// DefaultDialer returns the built-in Dialer.
func DefaultDialer() Dialer { return defaultDialer{} }

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
			return resp, nil //nolint:nilerr // truncated UDP answer is still useful when TCP setup fails
		}
		if r2, terr := tex.Exchange(ctx, q); terr == nil {
			return r2, nil
		}
	}
	return resp, nil
}

// ServeDNS implements acidns.Handler.
func (r *recursive) ServeDNS(ctx context.Context, w acidns.ResponseWriter, q wire.Message) {
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
		// DNSSEC bogus: map to SERVFAIL + EDE 6 (DNSSEC Bogus, RFC 8914).
		if errors.Is(err, errBogusAnswer) {
			ede := wire.NewExtendedError(wire.ExtendedErrorDNSSECBogus, "DNSSEC bogus")
			edns := wire.NewEDNSBuilder().UDPSize(1232).Option(ede).Build()
			_ = w.WriteMsg(must(b.RCODE(wire.RCODEServFail).EDNS(edns).Build()))
			return
		}
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
	if entry.AD {
		b = b.AuthenticData(true)
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

// errBogusAnswer is the internal sentinel for DNSSEC bogus answers; the
// Handler maps it to SERVFAIL+EDE6.
var errBogusAnswer = errors.New("recursive: dnssec bogus")

// Resolve returns a cached or freshly-iterated entry for (name, t).
func (r *recursive) Resolve(ctx context.Context, name wire.Name, t rrtype.Type) (Entry, error) {
	entry, err := r.resolveDepthFollow(ctx, name, t, 0, 0, nil)
	if err != nil {
		return Entry{}, err
	}
	if r.validator != nil {
		// Run validation on the leaf answer. We do NOT re-validate cache
		// hits separately: the cache stores Entry which carries AD; if AD
		// is set the upstream answer is trustworthy.
		res, err := r.validator.Resolve(ctx, name, t)
		if err != nil {
			return Entry{}, err
		}
		switch res.Result() {
		case StatusBogus:
			return Entry{}, errBogusAnswer
		case StatusSecure:
			entry.AD = true
		}
	}
	return entry, nil
}

// resolveDepthFollow handles CNAME chasing on top of the bare iterative
// resolution in resolveDepth. cnameSeen tracks visited owners to detect
// loops. depth bounds out-of-bailiwick NS recursion, cnameDepth bounds the
// CNAME chain.
func (r *recursive) resolveDepthFollow(ctx context.Context, name wire.Name, t rrtype.Type, depth, cnameDepth int, cnameSeen map[string]struct{}) (Entry, error) {
	if cnameDepth >= r.maxCNAMEs {
		return Entry{}, ErrCNAMELoop
	}
	if cnameSeen == nil {
		cnameSeen = make(map[string]struct{})
	}
	cur := name
	curT := t
	var aggregated Entry
	for {
		if _, seen := cnameSeen[cur.String()]; seen {
			return Entry{}, ErrCNAMELoop
		}
		cnameSeen[cur.String()] = struct{}{}

		entry, err := r.resolveDepth(ctx, cur, curT, depth)
		if err != nil {
			return Entry{}, err
		}
		// First leg becomes the spine of the response; subsequent legs
		// merge their answer records.
		if len(aggregated.Answer) == 0 && len(aggregated.Authority) == 0 {
			aggregated = entry
		} else {
			aggregated.Answer = append(aggregated.Answer, entry.Answer...)
			if entry.RCODE != wire.RCODENoError {
				aggregated.RCODE = entry.RCODE
			}
			if entry.ExpiresAt.Before(aggregated.ExpiresAt) {
				aggregated.ExpiresAt = entry.ExpiresAt
			}
		}

		// Did we land on a CNAME instead of qtype?
		if curT == rrtype.CNAME {
			return aggregated, nil
		}
		target, ok := pickCNAMETarget(entry.Answer, cur)
		if !ok {
			return aggregated, nil
		}
		// Did we already see qtype answers at the previous owner? If yes,
		// we're done.
		if hasTypeAt(entry.Answer, cur, curT) {
			return aggregated, nil
		}
		cnameDepth++
		if cnameDepth >= r.maxCNAMEs {
			return Entry{}, ErrCNAMELoop
		}
		cur = target
	}
}

func (r *recursive) resolveDepth(ctx context.Context, name wire.Name, t rrtype.Type, depth int) (Entry, error) {
	if depth >= r.maxDepth {
		return Entry{}, fmt.Errorf("recursive: depth limit reached for %s", name)
	}
	if e, ok := r.cache.Get(name, t); ok {
		return e, nil
	}

	servers := append([]netip.AddrPort(nil), r.roots...)
	for range r.maxIterations {
		if len(servers) == 0 {
			return Entry{}, fmt.Errorf("recursive: no servers to query for %s", name)
		}
		ranked := rankServers(r.stats, servers)
		resp, used, err := r.queryAny(ctx, ranked, name, t)
		if err != nil {
			return Entry{}, fmt.Errorf("recursive: query failed: %w", err)
		}
		// Lame check: REFUSED or SERVFAIL → mark and try next server set.
		rcode := resp.Flags().RCODE()
		if rcode == wire.RCODERefused || rcode == wire.RCODEServFail {
			r.stats.Record(used, 0, false)
			// Drop the lame server and retry remaining without re-querying
			// the failed one — but if we've exhausted the set, give up.
			servers = removeServer(ranked, used)
			if len(servers) == 0 {
				return Entry{}, ErrAllServersLame
			}
			continue
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

// queryAny tries servers in order, recording RTT/failure for each. Returns
// the response and the server that produced it.
func (r *recursive) queryAny(ctx context.Context, servers []netip.AddrPort, name wire.Name, t rrtype.Type) (wire.Message, netip.AddrPort, error) {
	id, err := randomID()
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	q, err := wire.NewBuilder().
		ID(id).
		Question(wire.NewQuestion(name, t)).
		EDNS(wire.NewEDNSBuilder().UDPSize(1232).Build()).
		Build()
	if err != nil {
		return nil, netip.AddrPort{}, err
	}

	var lastErr error
	for _, s := range servers {
		exchCtx := ctx
		var cancel context.CancelFunc
		if r.queryTimeout > 0 {
			exchCtx, cancel = context.WithTimeout(ctx, r.queryTimeout)
		}
		started := time.Now()
		resp, err := r.dialer.Exchange(exchCtx, s, q)
		if cancel != nil {
			cancel()
		}
		rtt := time.Since(started)
		if err == nil {
			r.stats.Record(s, rtt, true)
			return resp, s, nil
		}
		r.stats.Record(s, rtt, false)
		lastErr = err
		if ctx.Err() != nil {
			return nil, netip.AddrPort{}, ctx.Err()
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no servers")
	}
	return nil, netip.AddrPort{}, lastErr
}

// serversFromReferral picks the addresses to query next. It prefers in-message
// glue (additional section) but falls back to recursively resolving the NS
// targets for out-of-bailiwick delegations.
func (r *recursive) serversFromReferral(ctx context.Context, resp wire.Message, depth int) ([]netip.AddrPort, error) {
	var glued []netip.AddrPort
	var ungluedNS []wire.Name
	for _, auth := range resp.Authorities() {
		if auth.Type() != rrtype.NS {
			continue
		}
		ns, ok := wire.RDataAs[rdata.NS](auth)
		if !ok {
			continue
		}
		target := ns.NSDName()
		if addrs := glueFor(target, resp.Additionals()); len(addrs) > 0 {
			glued = append(glued, addrs...)
		} else {
			ungluedNS = append(ungluedNS, target)
		}
	}
	if len(glued) > 0 {
		return glued, nil
	}
	var out []netip.AddrPort
	for _, ns := range ungluedNS {
		entry, err := r.resolveDepth(ctx, ns, rrtype.A, depth+1)
		if err != nil {
			continue
		}
		for _, rec := range entry.Answer {
			if rec.Type() == rrtype.A {
				a, ok := wire.RDataAs[rdata.A](rec)
				if !ok {
					continue
				}
				out = append(out, netip.AddrPortFrom(a.Addr(), 53))
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
			a, ok := wire.RDataAs[rdata.A](add)
			if !ok {
				continue
			}
			out = append(out, netip.AddrPortFrom(a.Addr(), 53))
		case rrtype.AAAA:
			aaaa, ok := wire.RDataAs[rdata.AAAA](add)
			if !ok {
				continue
			}
			out = append(out, netip.AddrPortFrom(aaaa.Addr(), 53))
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

// pickCNAMETarget returns the CNAME target if records contains a CNAME at
// owner.
func pickCNAMETarget(records []wire.Record, owner wire.Name) (wire.Name, bool) {
	for _, r := range records {
		if r.Type() != rrtype.CNAME {
			continue
		}
		if !r.Name().Equal(owner) {
			continue
		}
		c, ok := wire.RDataAs[rdata.CNAME](r)
		if !ok {
			continue
		}
		return c.Target(), true
	}
	return wire.Name{}, false
}

func hasTypeAt(records []wire.Record, owner wire.Name, t rrtype.Type) bool {
	for _, r := range records {
		if r.Type() == t && r.Name().Equal(owner) {
			return true
		}
	}
	return false
}

// removeServer returns a copy of servers with target removed.
func removeServer(servers []netip.AddrPort, target netip.AddrPort) []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(servers))
	for _, s := range servers {
		if s == target {
			continue
		}
		out = append(out, s)
	}
	return out
}

func entryFromResponse(resp wire.Message) Entry {
	ttl := minTTL(60*time.Second, resp.Answers(), resp.Authorities())
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
		AD:         resp.Flags().AuthenticData(),
		ExpiresAt:  time.Now().Add(ttl),
	}
}

// negativeCacheTTL implements RFC 2308 §5.
func negativeCacheTTL(authority []wire.Record) time.Duration {
	for _, r := range authority {
		if r.Type() != rrtype.SOA {
			continue
		}
		soa, ok := wire.RDataAs[rdata.SOA](r)
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
