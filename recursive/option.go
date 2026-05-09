package recursive

import (
	"net/netip"
	"time"
)

// Option configures a Recursive at construction.
type Option interface{ applyRecursive(*config) }

type optionFunc func(*config)

func (f optionFunc) applyRecursive(c *config) { f(c) }

type config struct {
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
	resolveBudget  time.Duration
	allowNoRD      bool
	caseRandom     bool
	qnameMin       bool
	aggressiveNSEC bool
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

// WithDialer sets a custom Dialer.
func WithDialer(d Dialer) Option {
	return optionFunc(func(c *config) { c.dialer = d })
}

// WithResolveBudget sets a hard wall-clock cap on a single Resolve call,
// independent of WithQueryTimeout (which is per-exchange). Without this
// cap an adversarial graph can multiply (depth × iterations ×
// per-query timeout) into many minutes for a single query. Defaults
// to 30 seconds. A non-positive value disables the cap.
func WithResolveBudget(d time.Duration) Option {
	return optionFunc(func(c *config) { c.resolveBudget = d })
}

// WithMaxNegativeTTL caps the lifetime of negative cache entries. RFC
// 2308 §4 mandates a 24-hour upper bound regardless of the SOA's
// MINIMUM field; without this cap a hostile or misconfigured zone with
// a multi-year MINIMUM can pin NXDOMAIN/NoData entries far longer than
// operationally reasonable. A non-positive value disables the cap.
// Defaults to 1 hour.
func WithMaxNegativeTTL(d time.Duration) Option {
	return optionFunc(func(c *config) { c.maxNegTTL = d })
}

// WithAllowNoRD removes the safe default of refusing queries whose
// header has the Recursion Desired (RD) bit clear. Recursive
// resolvers that answer RD=0 queries are amplification primitives:
// any source can elicit large answers from cached zones without
// proving they want recursion, which is the classic open-resolver
// reflection vector. By default the resolver returns REFUSED to
// such queries.
//
// Set this only when the resolver is deployed as a cache-only
// "stub responder" intentionally serving the cache to non-recursive
// peers (e.g. an internal DNS appliance), and only after gating the
// listener with an ACL or rate limit middleware so the open-resolver
// risk is contained at the transport layer.
func WithAllowNoRD() Option {
	return optionFunc(func(c *config) { c.allowNoRD = true })
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
func WithAggressiveNSEC() Option {
	return optionFunc(func(c *config) { c.aggressiveNSEC = true })
}

// WithoutQNameMinimisation turns off RFC 9156 / 7816 QNAME
// minimisation. By default the resolver sends only the labels
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
// upstreams remain resolvable. Disable only if your environment
// has a very specific reason — e.g., a captive portal or
// split-horizon DNS where intermediate-name queries break in ways
// the fallback can't recover from.
func WithoutQNameMinimisation() Option {
	return optionFunc(func(c *config) { c.qnameMin = false })
}

// WithCaseRandomization enables RFC 5452 §9.3 0x20 hardening: the
// resolver randomly toggles the case of ASCII letters in the QNAME
// of every outbound query, then verifies the response's question
// section matches case-exactly. A spoofer that guesses the
// 16-bit transaction ID still has to also reproduce the case-pattern
// the resolver chose, multiplying the spoofing search space by 2^N
// for an N-letter qname.
//
// Defaults to off because some old or buggy authoritative servers
// silently lowercase the qname in their response, and rejecting
// those would lose resolution for the affected zones. Operators
// confident in their upstream's RFC 4343 compliance can opt in.
//
// Only the default Dialer honors this option; a caller-supplied
// custom Dialer is responsible for its own 0x20 implementation.
func WithCaseRandomization() Option {
	return optionFunc(func(c *config) { c.caseRandom = true })
}
