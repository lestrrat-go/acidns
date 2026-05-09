package recursive

import (
	"net/netip"
	"time"

	"github.com/lestrrat-go/option/v3"
)

// Option configures a Recursive at construction.
type Option interface {
	option.Interface
	recursiveOption()
}

type recursiveOption struct{ option.Interface }

func (recursiveOption) recursiveOption() {}

type config struct {
	roots              []netip.AddrPort
	cache              Cache
	stats              ServerStats
	maxIterations      int
	maxDepth           int
	maxCNAMEs          int
	maxInflight        int
	dialer             Dialer
	validator          Validator
	queryTimeout       time.Duration
	maxNegTTL          time.Duration
	maxPosTTL          time.Duration
	resolveBudget      time.Duration
	allowNoRD          bool
	caseRandom         bool
	qnameMin           bool
	aggressiveNSEC     bool
	upstreamQPS        float64
	upstreamBurst      float64
	upstreamMaxKeys    int
	upstreamMaxKeysSet bool
	rootPriming        bool
	rootRefresh        time.Duration
}

// rateLimit carries the (qps, burst) tuple for WithUpstreamRateLimit.
type rateLimit struct {
	qps   float64
	burst float64
}

type identRoots struct{}
type identCache struct{}
type identServerStats struct{}
type identMaxIterations struct{}
type identMaxDepth struct{}
type identMaxCNAMEDepth struct{}
type identQueryTimeout struct{}
type identValidator struct{}
type identDialer struct{}
type identResolveBudget struct{}
type identMaxNegativeTTL struct{}
type identMaxPositiveTTL struct{}
type identAllowNoRD struct{}
type identAggressiveNSEC struct{}
type identQNameMinimisation struct{}
type identCaseRandomization struct{}
type identUpstreamRateLimit struct{}
type identUpstreamRateLimitMaxKeys struct{}
type identMaxInflight struct{}
type identRootPriming struct{}

// WithRoots overrides the default root server list.
func WithRoots(addrs ...netip.AddrPort) Option {
	return recursiveOption{option.New(identRoots{}, addrs)}
}

// WithCache sets a custom Cache implementation.
func WithCache(c Cache) Option {
	return recursiveOption{option.New(identCache{}, c)}
}

// WithServerStats sets a custom ServerStats implementation. The default is
// an in-memory store.
func WithServerStats(s ServerStats) Option {
	return recursiveOption{option.New(identServerStats{}, s)}
}

// WithMaxIterations caps how many delegation steps a single query may
// traverse. Defaults to 30.
func WithMaxIterations(n int) Option {
	return recursiveOption{option.New(identMaxIterations{}, n)}
}

// WithMaxDepth caps the recursive resolveDepth nesting. CNAME chains
// and out-of-bailiwick NS resolution each consume one depth level;
// without a cap a hostile NS-graph can drive arbitrary recursion.
// Defaults to 8.
func WithMaxDepth(n int) Option {
	return recursiveOption{option.New(identMaxDepth{}, n)}
}

// WithMaxCNAMEDepth caps how many CNAME hops a single query may follow.
// Defaults to 8 — RFC 1035 doesn't specify a limit but every production
// resolver caps to defend against loops.
func WithMaxCNAMEDepth(n int) Option {
	return recursiveOption{option.New(identMaxCNAMEDepth{}, n)}
}

// WithQueryTimeout sets a per-query timeout that bounds each individual
// upstream exchange (independent of any caller-supplied context). Defaults
// to 4 seconds.
func WithQueryTimeout(d time.Duration) Option {
	return recursiveOption{option.New(identQueryTimeout{}, d)}
}

// WithValidator enables DNSSEC validation. The validator is invoked on
// every Resolve call; bogus answers become SERVFAIL responses bearing the
// configured EDE. The Resolver caches validated answers like any other.
func WithValidator(v Validator) Option {
	return recursiveOption{option.New(identValidator{}, v)}
}

// WithDialer sets a custom Dialer.
func WithDialer(d Dialer) Option {
	return recursiveOption{option.New(identDialer{}, d)}
}

// WithResolveBudget sets a hard wall-clock cap on a single Resolve call,
// independent of WithQueryTimeout (which is per-exchange). Without this
// cap an adversarial graph can multiply (depth × iterations ×
// per-query timeout) into many minutes for a single query. Defaults
// to 30 seconds. A non-positive value disables the cap.
func WithResolveBudget(d time.Duration) Option {
	return recursiveOption{option.New(identResolveBudget{}, d)}
}

// WithMaxNegativeTTL caps the lifetime of negative cache entries. RFC
// 2308 §4 mandates a 24-hour upper bound regardless of the SOA's
// MINIMUM field; without this cap a hostile or misconfigured zone with
// a multi-year MINIMUM can pin NXDOMAIN/NoData entries far longer than
// operationally reasonable. A non-positive value disables the cap.
// Defaults to 1 hour.
func WithMaxNegativeTTL(d time.Duration) Option {
	return recursiveOption{option.New(identMaxNegativeTTL{}, d)}
}

// WithMaxPositiveTTL caps the lifetime of positive cache entries. The
// RFC 1035 TTL field is unsigned 31-bit, so a hostile authoritative
// can pin a forged record for ~68 years; production resolvers
// universally cap this. A non-positive value disables the cap.
// Defaults to 24 hours, matching the forward handler.
func WithMaxPositiveTTL(d time.Duration) Option {
	return recursiveOption{option.New(identMaxPositiveTTL{}, d)}
}

// WithAllowNoRD toggles the safe default of refusing queries whose
// header has the Recursion Desired (RD) bit clear. Recursive
// resolvers that answer RD=0 queries are amplification primitives:
// any source can elicit large answers from cached zones without
// proving they want recursion, which is the classic open-resolver
// reflection vector. Default: refuse RD=0.
//
// Pass enable=true only when the resolver is deployed as a
// cache-only "stub responder" intentionally serving the cache to
// non-recursive peers (e.g. an internal DNS appliance), and only
// after gating the listener with an ACL or rate limit middleware so
// the open-resolver risk is contained at the transport layer.
func WithAllowNoRD(enable bool) Option {
	return recursiveOption{option.New(identAllowNoRD{}, enable)}
}

// WithAggressiveNSEC enables RFC 8198 Aggressive Use of
// DNSSEC-Validated Cache. When the resolver has a DNSSEC-validated
// NSEC record cached from a prior negative response, it can use
// that NSEC to synthesise NXDOMAIN locally for any other name that
// falls within the NSEC's interval, without contacting an
// authoritative server.
//
// Requires [WithValidator] — without DNSSEC validation, an
// attacker could poison the cache with fake NSECs to suppress
// resolution of arbitrary names. Setting this option without a
// validator is a no-op.
//
// Off by default. The current implementation covers NSEC-based
// NXDOMAIN synthesis; NSEC3 (hash-space lookup), NSEC NoData
// (type-bitmap inspection), and wildcard interaction are not yet
// covered — affected queries fall through to the regular iteration
// path.
func WithAggressiveNSEC(v bool) Option {
	return recursiveOption{option.New(identAggressiveNSEC{}, v)}
}

// WithQNameMinimisation toggles RFC 9156 / 7816 QNAME minimisation.
// When enabled (the default), the resolver sends only the labels
// needed to reach the next zone cut at each iteration step,
// revealing the full qname to authoritative servers only at the
// terminal hop (the zone authoritative for the qname's parent).
// This reduces information leakage to intermediate authoritatives —
// the root sees only TLDs, the TLD sees only second-level domains,
// etc.
//
// The implementation falls back to the full target qname on any
// "weird" intermediate response (NXDOMAIN at intermediate,
// SERVFAIL chain, answers at a non-target name) so non-conformant
// upstreams remain resolvable. Pass false only if your environment
// has a very specific reason — e.g., a captive portal or
// split-horizon DNS where intermediate-name queries break in ways
// the fallback can't recover from.
func WithQNameMinimisation(v bool) Option {
	return recursiveOption{option.New(identQNameMinimisation{}, v)}
}

// WithCaseRandomization toggles RFC 5452 §9.3 0x20 hardening.
// When enabled (the default), the resolver randomly toggles the
// case of ASCII letters in the QNAME of every outbound query and
// verifies the response's question section matches case-exactly,
// multiplying the off-path spoofing search space by 2^N for an
// N-letter qname.
//
// Pass false only when targeting an upstream known to silently
// lowercase the qname in responses (rare, but rejection would lose
// resolution for the affected zones). Modern authoritative servers
// preserve case per RFC 4343.
//
// Only the default Dialer honors this option; a caller-supplied
// custom Dialer is responsible for its own 0x20 implementation.
func WithCaseRandomization(v bool) Option {
	return recursiveOption{option.New(identCaseRandomization{}, v)}
}

// WithUpstreamRateLimit caps the outbound query rate per upstream
// authoritative server (keyed by IP+port) using a token bucket. qps
// is the steady-state refill rate in queries-per-second; burst is
// the maximum bucket size. burst <= 0 defaults to qps. qps <= 0
// disables the limiter entirely (this is the default).
//
// When the bucket for a candidate server is empty the resolver skips
// that server and tries the next ranked one. If every candidate is
// rate-limited, [ErrUpstreamRateLimited] is returned so callers can
// distinguish local throttling from upstream failure.
//
// This guards against unintentional DDoS of a single authoritative
// during pathological traffic patterns (e.g. a CNAME loop pinned to
// one TLD, or an attacker-driven query flood). It does not replace a
// proper edge rate limiter in front of the resolver.
func WithUpstreamRateLimit(qps, burst float64) Option {
	return recursiveOption{option.New(identUpstreamRateLimit{}, rateLimit{qps: qps, burst: burst})}
}

// WithUpstreamRateLimitMaxKeys caps the number of distinct upstream
// addresses tracked by [WithUpstreamRateLimit]. Without this cap
// the bucket map grows unbounded as the resolver visits more
// authoritatives, eventually exhausting memory under attacker-driven
// NS-graph trickery. When the cap is reached, idle (fully-refilled)
// buckets are evicted first, then the oldest-updated bucket. A
// non-positive value disables the cap. Defaults to 16384.
func WithUpstreamRateLimitMaxKeys(n int) Option {
	return recursiveOption{option.New(identUpstreamRateLimitMaxKeys{}, n)}
}

// WithMaxInflight caps the number of concurrent distinct cache-miss
// queries the resolver will dispatch. The existing single-flight map
// already coalesces concurrent queries for the same (qname, qtype),
// but does not cap the number of distinct outstanding entries; a
// random-subdomain attack flooding distinct names spawns one
// goroutine per unique key with no cap.
//
// When the cap is reached, further cache-miss queries fail fast with
// [ErrInflightFull] (callers see SERVFAIL); the cap rejects load the
// resolver cannot serve rather than queueing it. A non-positive value
// disables the cap. Defaults to 1024, matching the forward handler.
func WithMaxInflight(n int) Option {
	return recursiveOption{option.New(identMaxInflight{}, n)}
}

// WithRootPriming enables RFC 8109 root server priming: at startup
// the resolver issues a single NS . query against its configured
// root list and replaces the in-memory root set with whatever the
// authoritative reply contains. The query is repeated every refresh
// interval so the resolver tracks IANA's evolving root server list
// without requiring an operator restart.
//
// refresh <= 0 selects a sensible default (24 hours). The very first
// priming attempt is asynchronous; if it fails the resolver continues
// using the configured roots and retries on the next interval.
//
// Off by default. The configured roots from [WithRoots] (or the
// built-in IANA snapshot) are always used as the seed list — priming
// only refreshes them.
func WithRootPriming(refresh time.Duration) Option {
	return recursiveOption{option.New(identRootPriming{}, refresh)}
}
