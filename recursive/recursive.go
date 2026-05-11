package recursive

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/option/v3"
)

// ErrIterationLimit is returned when the resolver fails to reach an
// authoritative answer within the configured iteration cap.
var ErrIterationLimit = errors.New("recursive: iteration limit reached")

// ErrCNAMELoop is returned when a CNAME chain cycles or exceeds the depth
// cap.
var ErrCNAMELoop = errors.New("recursive: CNAME loop or chain too deep")

// ErrAllServersLame is the sentinel matched by [errors.Is] when every
// candidate server returned an unusable response (REFUSED, SERVFAIL,
// or no progress). The actual returned error is a concrete
// [*AllServersLameError] that wraps the per-server failures so
// callers can branch via the sentinel AND inspect each server's
// contribution via [errors.As] / [AllServersLameError.Servers].
var ErrAllServersLame = errors.New("recursive: all candidate servers lame")

// LameServer describes one server's contribution to an
// [AllServersLameError]: the address that was queried and the RCODE
// that classified the server as lame.
type LameServer struct {
	addr  netip.AddrPort
	rcode wire.RCODE
}

// Addr is the address of the lame server.
func (e *LameServer) Addr() netip.AddrPort { return e.addr }

// RCODE is the unusable RCODE the server returned (REFUSED or
// SERVFAIL).
func (e *LameServer) RCODE() wire.RCODE { return e.rcode }

// Error implements error.
func (e *LameServer) Error() string {
	return fmt.Sprintf("server %s: %s", e.addr, e.rcode)
}

// AllServersLameError is the concrete error type returned by the
// recursive resolver when every candidate server returned an
// unusable response. It wraps a [errors.Join] of [*LameServer]
// entries so callers can:
//
//   - match the sentinel: [errors.Is](err, [ErrAllServersLame])
//   - extract the bundle: var ae *AllServersLameError; [errors.As](err, &ae)
//   - find a single server: var ls *LameServer; [errors.As](err, &ls)
//     (returns the first lame server in the bundle)
//   - walk every server: ae.Servers() returns the full slice
type AllServersLameError struct {
	// joined is the result of errors.Join(*LameServer, ...). The
	// joined value's Unwrap() []error is what errors.Is/As walks
	// when searching for a per-server error.
	joined error
	// servers caches the typed slice so Servers() doesn't have to
	// re-walk joined; same backing data, typed.
	servers []*LameServer
}

// Servers returns the per-server entries in the order they were
// recorded. The returned slice ALIASES the wrapper's storage —
// callers MUST NOT mutate it.
func (e *AllServersLameError) Servers() []*LameServer { return e.servers }

// Error renders the sentinel headline followed by each per-server
// entry on its own line (delegated to errors.Join's stringer).
func (e *AllServersLameError) Error() string {
	if e.joined == nil {
		return ErrAllServersLame.Error()
	}
	return ErrAllServersLame.Error() + "\n" + e.joined.Error()
}

// Unwrap returns the joined per-server error so [errors.Is] and
// [errors.As] walk into the bundle.
func (e *AllServersLameError) Unwrap() error { return e.joined }

// Is reports whether target is [ErrAllServersLame]. Without this
// method, [errors.Is] would only walk the joined per-server entries
// and never match the package-level sentinel.
func (e *AllServersLameError) Is(target error) bool {
	return target == ErrAllServersLame
}

// newAllServersLameError builds an [*AllServersLameError] from the
// per-server entries accumulated during a resolveDepthInner walk.
// Returns a non-nil error even when servers is empty (callers should
// not invoke this with no entries; the empty case still produces a
// usable sentinel-matching error rather than nil).
func newAllServersLameError(servers []*LameServer) *AllServersLameError {
	errs := make([]error, len(servers))
	for i, s := range servers {
		errs[i] = s
	}
	return &AllServersLameError{
		joined:  errors.Join(errs...),
		servers: servers,
	}
}

// ErrTruncatedAfterTCPFail is returned when a UDP response had TC=1 and
// the TCP fallback failed: the truncated answer is incomplete and must
// not be cached or surfaced as authoritative. A network adversary that
// can drop packets on 53/tcp would otherwise be able to force the
// resolver to operate on partial data — including missing AD bits or
// stripped DNSSEC RRSIGs.
var ErrTruncatedAfterTCPFail = errors.New("recursive: TC=1 with TCP fallback failure")

// ErrInflightFull is returned when a cache miss arrives while the
// configured WithMaxInflight cap is saturated. Surfaces as SERVFAIL
// to clients via the ServeDNS handler. RFC 1035 doesn't define a
// specific RCODE for resource exhaustion; SERVFAIL matches operator
// expectations. Aliased to [acidns.ErrInflightFull] so callers can
// match either form via errors.Is.
var ErrInflightFull = acidns.ErrInflightFull

// ErrUpstreamRateLimited is returned when every candidate upstream
// server has been rate-limited by [WithUpstreamRateLimit] and there
// were no remaining unrestricted servers to try.
var ErrUpstreamRateLimited = errors.New("recursive: all upstream servers rate-limited")

// ErrMaintenanceAlreadyRunning is returned by [Recursive.RunMaintenance]
// when a previous call is still in progress on the same Recursive
// instance. Wiring RunMaintenance into both an admin-driven start and
// an autostart goroutine — the canonical way to hit this — would
// otherwise double the priming and sweep cadences.
var ErrMaintenanceAlreadyRunning = errors.New("recursive: RunMaintenance already running")

// ChainValidator is the contract recursive expects from a DNSSEC
// chain validator — an implementation that walks the chain of trust
// from a configured anchor down to (qname, qtype) and returns a
// classified validation outcome.
//
// The shape is structural so we avoid importing the validator
// package and creating an import cycle through the chain walker's
// Source path; in practice an [github.com/lestrrat-go/acidns/dnssec/validator.Walker]
// satisfies the call shape and is wrapped via a small adapter in
// caller code (the package-level Result int values match the
// validator package's, so the adapter is a one-liner).
//
// Renamed from `Validator` to disambiguate from
// [github.com/lestrrat-go/acidns/dnssec/validator.Validator] (the
// signature/RRsig verifier struct), which has a different API
// surface entirely.
type ChainValidator interface {
	Resolve(ctx context.Context, name wire.Name, t rrtype.Type) (ValidationResult, error)
}

// Validator is a deprecated alias for [ChainValidator].
//
// Deprecated: use [ChainValidator].
type Validator = ChainValidator

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

// Dialer abstracts how the resolver delivers a query to a chosen server.
type Dialer interface {
	Exchange(ctx context.Context, server netip.AddrPort, q wire.Message) (wire.Message, error)
}

// Recursive is the iterative recursive resolver. It implements
// [acidns.Handler] so it can be plugged into a server directly, and
// exposes Resolve for direct use. Construct via [New].
type Recursive struct {
	rootsMu        sync.RWMutex
	roots          []netip.AddrPort
	cache          Cache
	stats          ServerStats
	maxIterations  int
	maxDepth       int
	maxCNAMEs      int
	dialer         Dialer
	validator      Validator
	queryTimeout   time.Duration
	maxNegTTL      time.Duration
	maxPosTTL      time.Duration
	resolveBudget  time.Duration
	allowNoRD      bool
	caseRandom     bool
	qnameMin       bool
	aggressiveNSEC bool

	// nsecIdx caches DNSSEC-validated NSEC records for RFC 8198
	// aggressive synthesis. nil unless aggressiveNSEC is on (which
	// itself requires a validator).
	nsecIdx *nsecIndex

	// nsec3Idx is the NSEC3 counterpart — per-zone hash-space
	// indexes used to assemble the §5.3 closest-encloser proof
	// from cached NSEC3 records.
	nsec3Idx *nsec3Index

	// upstreamLim caps the per-AddrPort outbound query rate when
	// [WithUpstreamRateLimit] was supplied. nil disables.
	upstreamLim *upstreamLimiter

	// rootPriming and rootRefresh drive RFC 8109 root priming. When
	// rootPriming is true Run() performs an initial prime and then
	// refreshes on the rootRefresh cadence.
	rootPriming bool
	rootRefresh time.Duration

	inflightMu sync.Mutex
	inflight   map[string]*inflightCall

	// inflightSem caps the number of distinct concurrent cache-miss
	// resolutions. nil when WithMaxInflight ≤ 0. Acquisition is
	// non-blocking: a saturated semaphore surfaces [ErrInflightFull]
	// so callers can shed load (typically as SERVFAIL) rather than
	// queueing — queuing lets an attacker pin deeper resource pools.
	inflightSem chan struct{}

	// nsInProgressMu guards a Resolver-wide set of NS targets that
	// any goroutine is currently chasing. Sharing the set across
	// concurrent Resolves prevents the amplification an attacker
	// would otherwise gain by triggering many parallel walks of an
	// adversarial NS graph: the first walker marks the NS, every
	// other walker that hits the same name treats it as a cycle
	// and falls back to remaining alternatives instead of also
	// chasing it.
	nsInProgressMu sync.Mutex
	nsInProgress   map[string]struct{}

	// maintenanceRunning guards [Recursive.RunMaintenance] against
	// double-entry. A second concurrent call returns
	// [ErrMaintenanceAlreadyRunning] without spawning duplicate
	// tickers.
	maintenanceRunning atomic.Bool
}

// inflightCall coalesces concurrent resolveDepth invocations for the
// same (qname, qtype). When N goroutines miss the cache for the same
// key, only one performs the iterative walk; the others wait on done
// and reuse the result. RFC 5452 §6: each independent transmission is
// a fresh spoofing window, so without coalescing a thundering herd
// quadratically multiplies the attacker's chances.
type inflightCall struct {
	done  chan struct{}
	entry Entry
	err   error
}

// New returns a [*Recursive] resolver. Returns an error when option
// invariants are violated (e.g. WithAggressiveNSEC without
// WithValidator).
//
// When no [WithRoots] is supplied the resolver falls back to the
// IANA root server snapshot bundled with the package, so a
// zero-config New(...) works out of the box. Long-running daemons
// SHOULD pair this with [WithRootPriming] so the live list stays
// current as IANA reorganises operators.
func New(opts ...Option) (*Recursive, error) {
	c := config{
		maxIterations: 30,
		maxDepth:      8,
		maxCNAMEs:     8,
		maxInflight:   1024,
		queryTimeout:  4 * time.Second,
		maxNegTTL:     time.Hour,
		maxPosTTL:     24 * time.Hour,
		resolveBudget: 30 * time.Second,
		qnameMin:      true, // RFC 9156 recommended for production resolvers
		caseRandom:    true, // RFC 5452 §9.3 spoofing defence; pass WithCaseRandomization(false) to opt out
	}
	for _, o := range opts {
		switch o.Ident() {
		case identRoots{}:
			addrs := option.MustGet[[]netip.AddrPort](o)
			c.roots = append(c.roots[:0], addrs...)
		case identCache{}:
			c.cache = option.MustGet[Cache](o)
		case identServerStats{}:
			c.stats = option.MustGet[ServerStats](o)
		case identMaxIterations{}:
			c.maxIterations = option.MustGet[int](o)
		case identMaxDepth{}:
			c.maxDepth = option.MustGet[int](o)
		case identMaxCNAMEDepth{}:
			c.maxCNAMEs = option.MustGet[int](o)
		case identQueryTimeout{}:
			c.queryTimeout = option.MustGet[time.Duration](o)
		case identValidator{}:
			c.validator = option.MustGet[Validator](o)
		case identDialer{}:
			c.dialer = option.MustGet[Dialer](o)
		case identResolveBudget{}:
			c.resolveBudget = option.MustGet[time.Duration](o)
		case identMaxNegativeTTL{}:
			c.maxNegTTL = option.MustGet[time.Duration](o)
		case identMaxPositiveTTL{}:
			c.maxPosTTL = option.MustGet[time.Duration](o)
		case identAllowNoRD{}:
			c.allowNoRD = option.MustGet[bool](o)
		case identAggressiveNSEC{}:
			c.aggressiveNSEC = option.MustGet[bool](o)
		case identQNameMinimisation{}:
			c.qnameMin = option.MustGet[bool](o)
		case identCaseRandomization{}:
			c.caseRandom = option.MustGet[bool](o)
		case identUpstreamRateLimit{}:
			rl := option.MustGet[rateLimit](o)
			c.upstreamQPS = rl.qps
			c.upstreamBurst = rl.burst
		case identUpstreamRateLimitMaxKeys{}:
			c.upstreamMaxKeys = option.MustGet[int](o)
			c.upstreamMaxKeysSet = true
		case identMaxInflight{}:
			c.maxInflight = option.MustGet[int](o)
		case identRootPriming{}:
			c.rootPriming = true
			c.rootRefresh = option.MustGet[time.Duration](o)
		}
	}
	if c.aggressiveNSEC && c.validator == nil {
		return nil, fmt.Errorf("recursive: WithAggressiveNSEC requires WithValidator (RFC 8198 §5: aggressive use is only safe on validated answers)")
	}
	if c.cache == nil {
		c.cache = NewMemoryCache()
	}
	if c.stats == nil {
		c.stats = NewMemoryStats()
	}
	if c.dialer == nil {
		// caseRandom changes how the default dialer constructs its
		// per-query UDP exchanger; a caller-supplied custom dialer
		// is responsible for its own 0x20 verification.
		c.dialer = defaultDialer{use0x20: c.caseRandom}
	}
	r := &Recursive{
		roots:          append([]netip.AddrPort(nil), c.roots...),
		cache:          c.cache,
		stats:          c.stats,
		maxIterations:  c.maxIterations,
		maxDepth:       c.maxDepth,
		maxCNAMEs:      c.maxCNAMEs,
		dialer:         c.dialer,
		validator:      c.validator,
		queryTimeout:   c.queryTimeout,
		maxNegTTL:      c.maxNegTTL,
		maxPosTTL:      c.maxPosTTL,
		resolveBudget:  c.resolveBudget,
		allowNoRD:      c.allowNoRD,
		caseRandom:     c.caseRandom,
		qnameMin:       c.qnameMin,
		aggressiveNSEC: c.aggressiveNSEC,
		inflight:       make(map[string]*inflightCall),
		nsInProgress:   make(map[string]struct{}),
	}
	if c.maxInflight > 0 {
		r.inflightSem = make(chan struct{}, c.maxInflight)
	}
	if r.aggressiveNSEC {
		r.nsecIdx = newNSECIndex()
		r.nsec3Idx = newNSEC3Index()
	}
	if c.upstreamQPS > 0 {
		burst := c.upstreamBurst
		if burst <= 0 {
			burst = c.upstreamQPS
		}
		r.upstreamLim = newUpstreamLimiter(c.upstreamQPS, burst, nil)
		if c.upstreamMaxKeysSet {
			r.upstreamLim.maxKeys = c.upstreamMaxKeys
		}
	}
	if c.rootPriming {
		r.rootPriming = true
		r.rootRefresh = c.rootRefresh
		if r.rootRefresh <= 0 {
			r.rootRefresh = defaultRootRefreshInterval
		}
	}
	return r, nil
}

// DefaultDialer returns the built-in Dialer with the same defaults
// New() applies: RFC 5452 §9.3 0x20 case randomization on. Callers
// composing their own Recursive (e.g. with [WithDialer]) get the same
// spoofing defence as the package-default path.
func DefaultDialer() Dialer { return defaultDialer{use0x20: true} }

// defaultDialer is the Resolver's built-in Dialer. It is per-request
// stateless (no connection reuse) and constructs a fresh UDP
// exchanger on every Exchange call. use0x20 toggles RFC 5452 §9.3
// case randomization + verification on the UDP exchanger; the
// recursive resolver defaults it on and the caller can opt out via
// [WithCaseRandomization](false).
type defaultDialer struct {
	use0x20 bool
}

func (d defaultDialer) Exchange(ctx context.Context, server netip.AddrPort, q wire.Message) (wire.Message, error) {
	uex, err := acidns.NewUDPClient(server,
		acidns.WithUDPCaseRandomization(d.use0x20),
	)
	if err != nil {
		return wire.Message{}, err
	}
	resp, err := uex.Exchange(ctx, q)
	if err != nil {
		return wire.Message{}, err
	}
	if !resp.Flags().Truncated() {
		return resp, nil
	}
	// TC=1 means the response is incomplete. Re-issue over TCP per
	// RFC 7766 §5.2; if the TCP exchange cannot complete, the partial
	// UDP answer is unsafe to cache or surface (DNSSEC RRSIGs may
	// have been the records that didn't fit). Surface an error so the
	// caller can move on to the next candidate server rather than
	// quietly accept a degraded answer.
	tex, terr := acidns.NewTCPClient(server)
	if terr != nil {
		return wire.Message{}, fmt.Errorf("%w: tcp dial: %v", ErrTruncatedAfterTCPFail, terr)
	}
	// Re-randomise the transaction ID before the TCP retry. The UDP
	// query's ID is visible to any on-path observer; re-using it for the
	// TCP retry hands a free correlation point — and, worse, a known ID
	// to anyone attempting a TCP MITM — to attackers (RFC 5452 §10).
	id, terr := randomID()
	if terr != nil {
		return wire.Message{}, fmt.Errorf("%w: tcp id: %v", ErrTruncatedAfterTCPFail, terr)
	}
	r2, terr := tex.Exchange(ctx, wire.WithID(q, id))
	if terr != nil {
		return wire.Message{}, fmt.Errorf("%w: tcp exchange: %v", ErrTruncatedAfterTCPFail, terr)
	}
	return r2, nil
}

// ServeDNS implements acidns.Handler.
func (r *Recursive) ServeDNS(ctx context.Context, w acidns.ResponseWriter, q wire.Message) {
	b := wire.NewMessageBuilder().
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

	// The recursive resolver only operates on class IN. Hard-coding IN
	// throughout the iterative path means a non-IN question (e.g. CHAOS
	// id.server, RFC 4892) would be silently mistyped as IN at every
	// cache lookup and put. Refuse non-IN at the door with NOTIMP per
	// RFC 1035 §6.1.1; operators serving CHAOS should compose
	// chaos.NewHandler ahead of this resolver in the middleware chain.
	if question.Class() != rrtype.ClassIN {
		_ = w.WriteMsg(must(b.RCODE(wire.RCODENotImp).Build()))
		return
	}

	// A recursive resolver that answers queries without the RD bit is
	// an amplification primitive: any peer can elicit cached answers
	// without proving they wanted recursion, the classic open-resolver
	// reflection vector. Refuse such queries by default; operators that
	// intentionally publish their cache to non-recursive peers can opt
	// in via WithAllowNoRD after gating the listener with ACL / rate
	// limit middleware.
	if !q.Flags().RecursionDesired() && !r.allowNoRD {
		_ = w.WriteMsg(must(b.RCODE(wire.RCODERefused).Build()))
		return
	}

	entry, err := r.ResolveEntry(ctx, question.Name(), question.Type())
	if err != nil {
		// DNSSEC bogus: map to SERVFAIL + EDE 6 (DNSSEC Bogus, RFC 8914).
		if errors.Is(err, errBogusAnswer) {
			ede := wire.NewExtendedError(wire.ExtendedErrorDNSSECBogus, "DNSSEC bogus")
			edns, eerr := wire.NewEDNSBuilder().UDPSize(1232).Option(ede).Build()
			if eerr == nil {
				_ = w.WriteMsg(must(b.RCODE(wire.RCODEServFail).EDNS(edns).Build()))
			} else {
				_ = w.WriteMsg(must(b.RCODE(wire.RCODEServFail).Build()))
			}
			return
		}
		_ = w.WriteMsg(must(b.RCODE(wire.RCODEServFail).Build()))
		return
	}
	for _, rec := range entry.answer {
		b = b.Answer(rec)
	}
	for _, rec := range entry.authority {
		b = b.Authority(rec)
	}
	for _, rec := range entry.additional {
		b = b.Additional(rec)
	}
	if entry.rcode != wire.RCODENoError {
		b = b.RCODE(entry.rcode)
	}
	if entry.ad {
		b = b.AuthenticData(true)
	}
	_ = w.WriteMsg(must(b.Build()))
}

func must(m wire.Message, err error) wire.Message {
	if err != nil {
		fb, _ := wire.NewMessageBuilder().Response(true).RCODE(wire.RCODEServFail).Build()
		return fb
	}
	return m
}

// errBogusAnswer is the internal sentinel for DNSSEC bogus answers; the
// Handler maps it to SERVFAIL+EDE6.
var errBogusAnswer = errors.New("recursive: dnssec bogus")

// ResolveEntry returns a cached or freshly-iterated entry for (name, t).
//
// This signature deliberately differs from [acidns.Resolver.Resolve]:
// the cached [Entry] carries fields (authority, additional, AD bit,
// expiry) that an *acidns.Answer cannot represent. Callers that want
// Resolver semantics should construct an [acidns.Resolver] over this
// recursive instance via the resolver convenience layer; using
// ResolveEntry for the rich, cache-aware view is the recommended path
// for backend consumers.
func (r *Recursive) ResolveEntry(ctx context.Context, name wire.Name, t rrtype.Type) (Entry, error) {
	if r.resolveBudget > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.resolveBudget)
		defer cancel()
	}
	// Top-level cache hit: the entry has already been through the
	// validator (if any) on the resolution that populated it, and
	// carries the resulting AD bit. Returning it directly avoids
	// re-walking the validator on every repeated query — without this
	// short-circuit the cache becomes a bookkeeping detail rather than
	// a latency optimisation under DNSSEC, and a chained validator
	// implementation can amplify the per-cache-hit cost arbitrarily.
	if e, ok := r.cache.Get(name, rrtype.ClassIN, t); ok {
		return e, nil
	}
	// In-progress NS-resolution detection now lives on the Resolver
	// itself (see r.nsInProgress / r.markNSInProgress). The set is
	// shared across concurrent Resolve calls so an attacker cannot
	// amplify by triggering N parallel walks of an adversarial NS
	// graph; the first walker stakes the names and every other
	// walker that hits the same name treats it as a cycle.
	entry, err := r.resolveDepthFollow(ctx, name, t, 0, 0, nil)
	if err != nil {
		return Entry{}, err
	}
	if r.validator != nil {
		res, err := r.validator.Resolve(ctx, name, t)
		if err != nil {
			return Entry{}, err
		}
		switch res.Result() {
		case StatusBogus:
			return Entry{}, errBogusAnswer
		case StatusSecure:
			entry.ad = true
		}
	}
	// RFC 8198: harvest NSEC and NSEC3 records from a validated
	// negative response into the aggressive indexes. Both NXDOMAIN
	// (RCODE=3 with no answers) and NoData (RCODE=0 with no answers
	// and an SOA in authority) populate them.
	if r.aggressiveNSEC && entry.ad && len(entry.answer) == 0 &&
		(entry.rcode == wire.RCODENXDomain || entry.rcode == wire.RCODENoError) {
		now := time.Now()
		for _, ne := range extractValidatedNSECs(entry.authority, now) {
			r.nsecIdx.Insert(ne)
		}
		zoneApex, params, n3 := extractValidatedNSEC3s(entry.authority, now)
		if zoneApex.IsValid() {
			for _, e := range n3 {
				r.nsec3Idx.Insert(zoneApex, params, e)
			}
		}
	}
	return entry, nil
}

// resolveDepthFollow handles CNAME chasing on top of the bare iterative
// resolution in resolveDepth. cnameSeen tracks visited owners to detect
// loops. depth bounds out-of-bailiwick NS recursion, cnameDepth bounds the
// CNAME chain.
func (r *Recursive) resolveDepthFollow(ctx context.Context, name wire.Name, t rrtype.Type, depth, cnameDepth int, cnameSeen map[string]struct{}) (Entry, error) {
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
		// Filter each leg's answers to records the leg explicitly asked
		// about — same owner. RFC 5452 §5 + RFC 8499 §6: an
		// authoritative MAY return additional records along the chain,
		// but we don't trust them. A malicious authoritative for
		// `evil.example` returning `evil.example CNAME victim.bank.com`
		// PLUS a forged `victim.bank.com A 1.2.3.4` in the same answer
		// section would otherwise see the forged A flow into the
		// aggregated result. The next leg of the chase re-resolves the
		// CNAME target from roots, getting the legitimate records.
		legAnswers := recordsAt(entry.answer, cur)
		if len(aggregated.answer) == 0 && len(aggregated.authority) == 0 {
			aggregated = entry
			aggregated.answer = legAnswers
		} else {
			aggregated.answer = append(aggregated.answer, legAnswers...)
			if entry.rcode != wire.RCODENoError {
				aggregated.rcode = entry.rcode
			}
			if entry.expiresAt.Before(aggregated.expiresAt) {
				aggregated.expiresAt = entry.expiresAt
			}
		}

		// Did we land on a CNAME instead of qtype?
		if curT == rrtype.CNAME {
			return aggregated, nil
		}
		target, ok := pickCNAMETarget(entry.answer, cur)
		if !ok {
			return aggregated, nil
		}
		// Did we already see qtype answers at the previous owner? If yes,
		// we're done.
		if hasTypeAt(entry.answer, cur, curT) {
			return aggregated, nil
		}
		cnameDepth++
		if cnameDepth >= r.maxCNAMEs {
			return Entry{}, ErrCNAMELoop
		}
		cur = target
	}
}

// recordsAt returns the subset of records whose owner equals name. Used
// during CNAME chasing to discard "extra" records an authoritative
// server may have bundled alongside the requested data — the resolver
// re-resolves the chase target from roots, so trusting the bundled
// records would let one zone forge data for another.
func recordsAt(records []wire.Record, name wire.Name) []wire.Record {
	out := make([]wire.Record, 0, len(records))
	for _, r := range records {
		if r.Name().Equal(name) {
			out = append(out, r)
		}
	}
	return out
}

func (r *Recursive) resolveDepth(ctx context.Context, name wire.Name, t rrtype.Type, depth int) (Entry, error) {
	if depth >= r.maxDepth {
		return Entry{}, fmt.Errorf("recursive: depth limit reached for %s", name)
	}
	if e, ok := r.cache.Get(name, rrtype.ClassIN, t); ok {
		return e, nil
	}
	// RFC 8198 aggressive NSEC: before going to the network, check
	// whether a previously-validated NSEC in the index already
	// proves NXDOMAIN for this name. If yes, synthesise the answer
	// locally — no upstream traffic, no information leak. The
	// synthesised entry is also written to the regular cache so the
	// next lookup hits the standard fast path above.
	if e, ok := r.synthesiseFromNSEC(name, t); ok {
		r.cache.Put(name, rrtype.ClassIN, t, e)
		return e, nil
	}
	if e, ok := r.synthesiseFromNSEC3(name, t); ok {
		r.cache.Put(name, rrtype.ClassIN, t, e)
		return e, nil
	}

	// Singleflight: coalesce concurrent misses for the same key.
	// Both leader and followers wait on <-call.done vs their own
	// ctx.Done(). The iterative work itself runs in a dedicated
	// goroutine under a context detached from any individual caller
	// (see startResolveDepth) so a cancelled leader cannot strand the
	// followers — RFC 5452 §6 spoofing window amplification would
	// otherwise multiply with every aborted leader (each surviving
	// follower having to re-issue the full iterative walk).
	key := nameKey(name) + "\x00" + fmt.Sprintf("%d", t)
	r.inflightMu.Lock()
	call, ok := r.inflight[key]
	if !ok {
		// Try to acquire a slot in the inflight semaphore before
		// publishing a new call entry. Followers (the same key)
		// pay no slot — they share the leader's. Distinct
		// cache-miss keys each cost a slot; saturation surfaces
		// ErrInflightFull so callers can shed load.
		if r.inflightSem != nil {
			select {
			case r.inflightSem <- struct{}{}:
			default:
				r.inflightMu.Unlock()
				return Entry{}, ErrInflightFull
			}
		}
		call = &inflightCall{done: make(chan struct{})}
		r.inflight[key] = call
		r.startResolveDepth(ctx, call, key, name, t, depth)
	}
	r.inflightMu.Unlock()

	select {
	case <-call.done:
		return call.entry, call.err
	case <-ctx.Done():
		return Entry{}, ctx.Err()
	}
}

// startResolveDepth spawns the goroutine that drives resolveDepthInner
// for the given inflight call. The goroutine's context detaches the
// caller's cancellation via [context.WithoutCancel] — so a cancelled
// leader does not abort an in-flight iterative walk that other waiters
// still need — while preserving caller-installed values (slog
// correlation ids, trace spans, …) for observers down the stack.
// The detached context is bounded by resolveBudget (or queryTimeout
// when resolveBudget is unset) so the work cannot run forever once
// every caller has dropped.
//
// This mirrors forward.startExchange. See the regression test
// TestResolveSingleflightLeaderCancelDoesNotOrphanFollowers.
func (r *Recursive) startResolveDepth(callerCtx context.Context, call *inflightCall, key string, name wire.Name, t rrtype.Type, depth int) {
	go func() {
		defer func() {
			r.inflightMu.Lock()
			delete(r.inflight, key)
			r.inflightMu.Unlock()
			if r.inflightSem != nil {
				<-r.inflightSem
			}
			close(call.done)
		}()
		// Detach from callerCtx so a leader cancel does not orphan
		// followers. Preserve caller values (slog ids, trace spans).
		innerCtx := context.WithoutCancel(callerCtx)
		// Bound the detached work so it cannot run forever once the
		// last waiter has dropped. resolveBudget is the natural
		// upper bound (ResolveEntry already applies it on the
		// caller side); falling back to queryTimeout keeps a sane
		// ceiling when neither has been configured by a custom
		// caller bypassing ResolveEntry.
		bound := r.resolveBudget
		if bound <= 0 {
			bound = r.queryTimeout
		}
		if bound > 0 {
			var cancel context.CancelFunc
			innerCtx, cancel = context.WithTimeout(innerCtx, bound)
			defer cancel()
		}
		entry, err := r.resolveDepthInner(innerCtx, name, t, depth)
		call.entry = entry
		call.err = err
	}()
}

func (r *Recursive) resolveDepthInner(ctx context.Context, target wire.Name, t rrtype.Type, depth int) (Entry, error) {
	servers := r.currentRoots()
	// closestZone tracks the deepest known authoritative zone the
	// resolver has confirmed via referral. Starts at the root and
	// advances on each referral (or each authoritative ENT at a
	// minimised name). Used to compute the next minimised qname per
	// RFC 9156 §2.3.
	closestZone := wire.RootName()
	// fellBack flips true when a minimised query produces a result
	// that demands a re-query with the full target qname (NXDOMAIN
	// at intermediate, server returned answers at intermediate, etc.
	// — see RFC 9156 §2.4 fallback rules). When set, every
	// subsequent query in this resolution sends target directly.
	fellBack := !r.qnameMin
	// lameServers accumulates one [*LameServer] per server that
	// returned an unusable response. On all-exhausted return the
	// slice is wrapped in an [*AllServersLameError] so callers can
	// inspect every server's contribution. Survives the minimised →
	// fallback transition so the operator sees both passes' failures
	// when both are exhausted.
	var lameServers []*LameServer

	for range r.maxIterations {
		if len(servers) == 0 {
			return Entry{}, fmt.Errorf("recursive: no servers to query for %s", target)
		}

		// Choose the qname for this step. Without qmin (or after a
		// fallback) we always query target. With qmin, we query the
		// minimised name; if that's already target, we naturally
		// progress to the terminal query.
		queryName := target
		if !fellBack {
			queryName = minimisedQName(closestZone, target)
		}

		ranked := rankServers(r.stats, servers)
		resp, used, err := r.queryAny(ctx, ranked, queryName, t)
		if err != nil {
			return Entry{}, fmt.Errorf("recursive: query failed: %w", err)
		}
		rcode := resp.Flags().RCODE()

		// Lame check: REFUSED or SERVFAIL → mark and try next server set.
		if rcode == wire.RCODERefused || rcode == wire.RCODEServFail {
			r.stats.Record(used, 0, false)
			lameServers = append(lameServers, &LameServer{addr: used, rcode: rcode})
			servers = removeServer(ranked, used)
			if len(servers) == 0 {
				// RFC 9156 §2.4.3: if the upstream chain refuses a
				// minimised query, retry the same step with target so
				// servers that misimplement the algorithm still answer.
				if !fellBack {
					fellBack = true
					servers = ranked
					continue
				}
				return Entry{}, newAllServersLameError(lameServers)
			}
			continue
		}

		// Authoritative answer is terminal IF this was the target
		// query; otherwise it's a minimised-step result that we
		// classify per RFC 9156 §2.4.
		if resp.Flags().Authoritative() {
			if queryName.Equal(target) {
				entry := r.entryFromResponse(target, resp)
				r.cache.Put(target, rrtype.ClassIN, t, entry)
				return entry, nil
			}
			// Intermediate authoritative response.
			if rcode == wire.RCODENoError && len(resp.Answers()) == 0 {
				// Empty non-terminal: name exists, no records of t. Advance.
				closestZone = queryName
				continue
			}
			// NXDOMAIN at intermediate (RFC 9156 §2.4.2 — server may
			// misimplement ENTs) or unexpected answers at intermediate
			// (DNAME, wildcard, mis-zoned data). Fall back to target.
			fellBack = true
			continue
		}

		// Non-authoritative: prefer following any delegation in
		// the authority section. A path-injected forgery typically
		// lacks a coherent delegation chain.
		next := r.serversFromReferral(ctx, resp, depth)
		if len(next) > 0 {
			servers = next
			if rz := referralZone(resp); rz.IsValid() {
				closestZone = rz
			}
			continue
		}
		if queryName.Equal(target) && hasAnswerFor(resp, target, t) {
			entry := r.entryFromResponse(target, resp)
			r.cache.Put(target, rrtype.ClassIN, t, entry)
			return entry, nil
		}
		// No referral and not the target query — fall back to target.
		if !fellBack {
			fellBack = true
			continue
		}
		return Entry{}, fmt.Errorf("recursive: empty referral for %s", target)
	}
	return Entry{}, ErrIterationLimit
}

// minimisedQName returns the qname to send for the next iteration
// step under RFC 9156 §2.3. It is target with all but
// (closestZone.NumLabels() + 1) trailing labels stripped — i.e.,
// one label longer than the closest known zone, reaching toward
// target. When the resulting name would equal or exceed target's
// length, target is returned (the iteration has reached the
// authoritative server for target's parent zone and the next query
// is the real one).
func minimisedQName(closestZone, target wire.Name) wire.Name {
	encLabels := closestZone.NumLabels()
	n := target
	for n.NumLabels() > encLabels+1 {
		p, ok := n.Parent()
		if !ok || n.Equal(p) {
			return target
		}
		n = p
	}
	return n
}

// queryAny tries servers in order, recording RTT/failure for each. Returns
// the response and the server that produced it. A fresh transaction ID is
// generated for every transmission so a late datagram from a slow server
// can't be confused with the next server's reply (RFC 5452 §5).
func (r *Recursive) queryAny(ctx context.Context, servers []netip.AddrPort, name wire.Name, t rrtype.Type) (wire.Message, netip.AddrPort, error) {
	var lastErr error
	var skippedRateLimit bool
	for _, s := range servers {
		// Per-upstream rate limit. When the bucket is empty for this
		// server, fall through to the next ranked candidate rather
		// than blocking — typical recursive deployments have multiple
		// authoritative servers per zone and the ranking already
		// prefers the fastest. If every candidate is rate-limited we
		// surface a typed error so the caller can react.
		if !r.upstreamLim.Take(s) {
			skippedRateLimit = true
			continue
		}
		id, err := randomID()
		if err != nil {
			return wire.Message{}, netip.AddrPort{}, err
		}
		ed, err := wire.NewEDNSBuilder().UDPSize(1232).Build()
		if err != nil {
			return wire.Message{}, netip.AddrPort{}, err
		}
		q, err := wire.NewMessageBuilder().
			ID(id).
			Question(wire.NewQuestion(name, t)).
			EDNS(ed).
			Build()
		if err != nil {
			return wire.Message{}, netip.AddrPort{}, err
		}

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
			return wire.Message{}, netip.AddrPort{}, ctx.Err()
		}
	}
	if lastErr == nil {
		if skippedRateLimit {
			lastErr = ErrUpstreamRateLimited
		} else {
			lastErr = errors.New("no servers")
		}
	}
	return wire.Message{}, netip.AddrPort{}, lastErr
}

// serversFromReferral picks the addresses to query next. It prefers
// in-bailiwick glue from the additional section and falls back to
// recursively resolving the NS targets for out-of-bailiwick delegations.
//
// Glue is only trusted when both the NS target and the glue's owner are
// at-or-below the delegating zone (the owner of the NS RRset). RFC 5452
// §5.4.1 — accepting out-of-bailiwick glue lets a malicious nameserver
// poison arbitrary names by stuffing the additional section with A
// records for unrelated owners.
func (r *Recursive) serversFromReferral(ctx context.Context, resp wire.Message, depth int) []netip.AddrPort {
	zone := referralZone(resp)
	var glued []netip.AddrPort
	var ungluedNS []wire.Name
	for _, auth := range resp.Authorities() {
		if auth.Type() != rrtype.NS {
			continue
		}
		// All NS records in a referral must share the same owner (the
		// delegating zone). A different owner is anomalous; skip it.
		if zone.IsValid() && !auth.Name().Equal(zone) {
			continue
		}
		ns, ok := wire.RDataAs[rdata.NS](auth)
		if !ok {
			continue
		}
		target := ns.Target()
		if zone.IsValid() && inBailiwick(zone, target) {
			if addrs := glueFor(target, resp.Additionals(), zone); len(addrs) > 0 {
				glued = append(glued, addrs...)
				continue
			}
		}
		ungluedNS = append(ungluedNS, target)
	}
	if len(glued) > 0 {
		return glued
	}
	var out []netip.AddrPort
	for _, ns := range ungluedNS {
		out = append(out, r.resolveUngluedNS(ctx, ns, depth)...)
	}
	return out
}

// resolveUngluedNS performs the global in-progress claim + parallel
// A/AAAA resolution for a single out-of-bailiwick NS target. It is
// split out of serversFromReferral so that `defer unmarkNSInProgress`
// runs at each iteration's boundary rather than accumulating until
// the caller returns — and so a panic anywhere between mark and the
// goroutines' completion still releases the claim. Without the
// defer, a panic in this body would permanently strand the NS in
// the resolver-wide in-progress map, silently breaking that NS for
// the lifetime of the process.
func (r *Recursive) resolveUngluedNS(ctx context.Context, ns wire.Name, depth int) []netip.AddrPort {
	nsKey := nameKey(ns)
	// Resolver-wide cycle set: if any goroutine (this one OR a
	// concurrent Resolve) is currently chasing ns up its NS
	// graph, treat it as a cycle and skip. This collapses the
	// per-Resolve cycle detection (which only protected against
	// in-stack loops) into a global guard that also bounds the
	// amplification an attacker would gain from triggering many
	// parallel walks of an adversarial graph.
	if !r.markNSInProgress(nsKey) {
		return nil
	}
	defer r.unmarkNSInProgress(nsKey)
	// Resolve A and AAAA in parallel — there's no causal
	// dependency between them and the recursive walks they
	// trigger don't share contention beyond the cache. Halving
	// the latency on every NS-target resolution compounds
	// noticeably across the full delegation chain. Result
	// ordering is preserved: A first, then AAAA, matching the
	// dual-stack preference of most callers.
	var (
		a4Addrs []netip.AddrPort
		a6Addrs []netip.AddrPort
		wg      sync.WaitGroup
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		a4Entry, err := r.resolveDepth(ctx, ns, rrtype.A, depth+1)
		if err != nil {
			return
		}
		for _, rec := range a4Entry.answer {
			if a, ok := wire.RDataAs[rdata.A](rec); ok {
				a4Addrs = append(a4Addrs, netip.AddrPortFrom(a.Addr(), 53))
			}
		}
	}()
	go func() {
		defer wg.Done()
		a6Entry, err := r.resolveDepth(ctx, ns, rrtype.AAAA, depth+1)
		if err != nil {
			return
		}
		for _, rec := range a6Entry.answer {
			if aaaa, ok := wire.RDataAs[rdata.AAAA](rec); ok {
				a6Addrs = append(a6Addrs, netip.AddrPortFrom(aaaa.Addr(), 53))
			}
		}
	}()
	wg.Wait()
	out := make([]netip.AddrPort, 0, len(a4Addrs)+len(a6Addrs))
	out = append(out, a4Addrs...)
	out = append(out, a6Addrs...)
	return out
}

// markNSInProgress atomically claims ns. Returns true if the caller
// should proceed with chasing ns; false if some goroutine is
// already chasing it and this caller should skip ahead to the next
// candidate. The caller must call [unmarkNSInProgress] on the same
// key on success.
func (r *Recursive) markNSInProgress(nsKey string) bool {
	r.nsInProgressMu.Lock()
	defer r.nsInProgressMu.Unlock()
	if _, busy := r.nsInProgress[nsKey]; busy {
		return false
	}
	r.nsInProgress[nsKey] = struct{}{}
	return true
}

func (r *Recursive) unmarkNSInProgress(nsKey string) {
	r.nsInProgressMu.Lock()
	delete(r.nsInProgress, nsKey)
	r.nsInProgressMu.Unlock()
}

// referralZone returns the owner name of the NS RRset in resp's
// authority section — i.e., the zone that owns the delegation. If no NS
// is present (the referral is malformed), an invalid Name is returned
// and the caller falls back to out-of-bailiwick recursion.
func referralZone(resp wire.Message) wire.Name {
	for _, auth := range resp.Authorities() {
		if auth.Type() == rrtype.NS {
			return auth.Name()
		}
	}
	return wire.Name{}
}

// inBailiwick reports whether descendant is at-or-below ancestor.
func inBailiwick(ancestor, descendant wire.Name) bool {
	cur := descendant
	for cur.IsValid() {
		if cur.Equal(ancestor) {
			return true
		}
		p, ok := cur.Parent()
		if !ok || cur.Equal(p) {
			return false
		}
		cur = p
	}
	return false
}

// glueFor extracts in-bailiwick A/AAAA glue records for target from the
// additional section. zone is the delegating zone — glue records owned
// by a name outside the zone are not trustworthy and are skipped.
func glueFor(target wire.Name, additional []wire.Record, zone wire.Name) []netip.AddrPort {
	var out []netip.AddrPort
	for _, add := range additional {
		if !add.Name().Equal(target) {
			continue
		}
		if zone.IsValid() && !inBailiwick(zone, add.Name()) {
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

func (r *Recursive) entryFromResponse(qname wire.Name, resp wire.Message) Entry {
	ttl := minTTL(60*time.Second, resp.Answers(), resp.Authorities())
	if len(resp.Answers()) == 0 {
		if neg := negativeCacheTTL(resp.Authorities()); neg > 0 && neg < ttl {
			ttl = neg
		}
		// RFC 2308 §4 caps negative caching at 24 hours; we apply
		// the configured (smaller-by-default) limit here so a
		// hostile zone with a multi-year SOA MINIMUM cannot pin
		// NXDOMAIN/NoData entries.
		if r.maxNegTTL > 0 && ttl > r.maxNegTTL {
			ttl = r.maxNegTTL
		}
	} else if r.maxPosTTL > 0 && ttl > r.maxPosTTL {
		// Cap positive TTLs so a hostile authoritative cannot pin a
		// forged record for the lifetime of the process by claiming
		// TTL = 2^31-1.
		ttl = r.maxPosTTL
	}
	answers, authority, additional := bailiwickFilter(qname, resp)
	// AD bit from upstream is meaningless without local validation —
	// any path-injecting attacker could set AD=1 on a forged answer
	// and a non-validating resolver would otherwise propagate it. Trust
	// AD only when the validator is wired in; the validator overwrites
	// this field on its way through ResolveEntry when present.
	ad := false
	if r.validator != nil {
		ad = resp.Flags().AuthenticData()
	}
	return Entry{
		answer:     answers,
		authority:  authority,
		additional: additional,
		rcode:      resp.Flags().RCODE(),
		aa:         resp.Flags().Authoritative(),
		ad:         ad,
		expiresAt:  time.Now().Add(ttl),
	}
}

// isDNSSECDenialType reports whether t is a record type that
// participates in a denial-of-existence proof and is expected to
// appear with owner names spanning the signed zone — not just
// at-or-above the qname. RRSIG carries a signature over an NSEC or
// NSEC3 RRset; its owner mirrors the covered RRset's owner.
func isDNSSECDenialType(t rrtype.Type) bool {
	switch t {
	case rrtype.NSEC, rrtype.NSEC3, rrtype.RRSIG:
		return true
	}
	return false
}

// bailiwickFilter sanitises a terminal response before it is cached or
// returned to the caller. It enforces RFC 5452 §6: a malicious upstream
// must not be able to insert records for unrelated owners by stuffing the
// answer/authority/additional sections of a response to qname.
//
//   - Answer: keep records whose owner is qname or a CNAME target reachable
//     from qname through the answer's own chain. Out-of-chain records (the
//     "Kashpureff" injection) are dropped.
//   - Authority: keep records whose owner is at-or-above qname (zone-level
//     SOA/NS), since those are the only authority records relevant to a
//     terminal answer for qname. Records owned at the DNS root (".") are
//     rejected when qname is not the root itself — a legitimate upstream
//     never claims authority at the root for a non-root qname, and
//     admitting one would let a hostile upstream gate forged NSEC records
//     covering arbitrary names through the cache-poisoning filter via the
//     root-owned SOA path.
//   - Additional: keep OPT and records whose owner is referenced by a kept
//     Answer-section CNAME target or Authority-section NS rdata, and whose
//     owner is at-or-below the deepest ancestor we kept in Authority (the
//     closest enclosing zone). Everything else — and in particular A/AAAA
//     records for unrelated names — is discarded.
func bailiwickFilter(qname wire.Name, resp wire.Message) (answers, authority, additional []wire.Record) {
	chain := map[string]struct{}{nameKey(qname): {}}
	for {
		grew := false
		for _, r := range resp.Answers() {
			if r.Type() != rrtype.CNAME {
				continue
			}
			if _, ok := chain[nameKey(r.Name())]; !ok {
				continue
			}
			c, ok := wire.RDataAs[rdata.CNAME](r)
			if !ok {
				continue
			}
			tk := nameKey(c.Target())
			if _, exists := chain[tk]; exists {
				continue
			}
			chain[tk] = struct{}{}
			grew = true
		}
		if !grew {
			break
		}
	}

	answers = make([]wire.Record, 0, len(resp.Answers()))
	for _, r := range resp.Answers() {
		if _, ok := chain[nameKey(r.Name())]; ok {
			answers = append(answers, r)
		}
	}

	// The SOA owner in the authority section names the signed zone.
	// DNSSEC denial-of-existence proofs (NSEC, NSEC3, and their
	// covering RRSIGs) are owned by names anywhere within that zone,
	// including siblings of qname — that's the whole point of an
	// NSEC interval. Treat those record types as legitimate when
	// they fall at-or-below the SOA owner; the strict
	// "ancestor-of-qname" check would otherwise drop the very NSEC
	// that proves the response.
	var soaOwner wire.Name
	for _, r := range resp.Authorities() {
		if r.Type() == rrtype.SOA {
			soaOwner = r.Name()
			break
		}
	}
	// The SOA owner only earns the right to gate denial records when
	// it is itself an ancestor of qname. Without this, a hostile
	// authoritative for a sibling zone could attach a SOA owned at a
	// parent of an unrelated victim zone (e.g. SOA for .tld plus
	// crafted NSECs covering bank.tld) and the filter would admit the
	// crafted denial records into the cached authority section.
	// Validation downstream catches this when DNSSEC is on, but a
	// validator-off path then surfaces the records to callers.
	//
	// Reject a root-owned SOA outright when qname is not the root: a
	// legitimate upstream never answers "bank.example." with SOA
	// owned at ".", but inBailiwick(., qname) returns true for any
	// qname (root is the ancestor of everything), which would
	// otherwise let a hostile upstream stuff root-owned NSECs
	// covering arbitrary names into the authority section and pass
	// the bailiwick check. The validator catches this for signed
	// responses, but defence-in-depth — and the validator-off path
	// — requires rejecting it here. Mirrors the same rule applied
	// by forward.filterBailiwick.
	if soaOwner.IsValid() && !inBailiwick(soaOwner, qname) {
		soaOwner = wire.Name{}
	}
	if soaOwner.IsRoot() && !qname.IsRoot() {
		soaOwner = wire.Name{}
	}
	authority = make([]wire.Record, 0, len(resp.Authorities()))
	for _, r := range resp.Authorities() {
		// Reject any authority record owned at the DNS root when
		// qname is not the root itself (see SOA-owner rationale
		// above). This drops the crafted root-owned SOA and any
		// root-owned denial records before they can be cached.
		if r.Name().IsRoot() && !qname.IsRoot() {
			continue
		}
		if inBailiwick(r.Name(), qname) {
			authority = append(authority, r)
			continue
		}
		if soaOwner.IsValid() && isDNSSECDenialType(r.Type()) && inBailiwick(soaOwner, r.Name()) {
			authority = append(authority, r)
		}
	}

	zoneCut := deepestAncestor(authority, qname)

	referenced := map[string]struct{}{}
	for _, r := range answers {
		if c, ok := wire.RDataAs[rdata.CNAME](r); ok {
			referenced[nameKey(c.Target())] = struct{}{}
		}
	}
	for _, r := range authority {
		if ns, ok := wire.RDataAs[rdata.NS](r); ok {
			referenced[nameKey(ns.Target())] = struct{}{}
		}
	}

	additional = make([]wire.Record, 0, len(resp.Additionals()))
	for _, r := range resp.Additionals() {
		if r.Type() == rrtype.OPT {
			additional = append(additional, r)
			continue
		}
		if _, ok := referenced[nameKey(r.Name())]; !ok {
			continue
		}
		if zoneCut.IsValid() && !inBailiwick(zoneCut, r.Name()) {
			continue
		}
		additional = append(additional, r)
	}
	return answers, authority, additional
}

// deepestAncestor returns the deepest owner among authority records that
// is at-or-above qname; this is the closest enclosing zone the response
// claims authority over and bounds what owners we will accept in the
// additional section.
func deepestAncestor(authority []wire.Record, qname wire.Name) wire.Name {
	var best wire.Name
	for _, r := range authority {
		if !inBailiwick(r.Name(), qname) {
			continue
		}
		if !best.IsValid() || r.Name().WireLen() > best.WireLen() {
			best = r.Name()
		}
	}
	return best
}

func nameKey(n wire.Name) string {
	return string(n.AppendWire(nil))
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
		minTTL := soa.Minimum()
		if r.TTL() < minTTL {
			return r.TTL()
		}
		return minTTL
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
