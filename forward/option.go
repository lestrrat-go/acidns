package forward

import (
	"crypto/tls"
	"log/slog"
	"net/netip"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/option/v3"
)

// Option configures a forward Forwarder.
type Option interface {
	option.Interface
	forwardOption()
}

type forwardOption struct{ option.Interface }

func (forwardOption) forwardOption() {}

type config struct {
	upstream     acidns.Exchanger
	upstreamName string
	cacheSize    int
	minTTL       time.Duration
	maxTTL       time.Duration
	maxNegTTL    time.Duration
	queryTimeout time.Duration
	maxInflight  int
	now          func() time.Time
	logger       *slog.Logger
	allowNoRD    bool
}

type identUpstream struct{}
type identUDPUpstream struct{}
type identDoTUpstream struct{}
type identCacheSize struct{}
type identMinTTL struct{}
type identMaxTTL struct{}
type identMaxNegTTL struct{}
type identQueryTimeout struct{}
type identMaxInflight struct{}
type identClock struct{}
type identLogger struct{}
type identAllowNoRD struct{}

// dotUpstreamSpec carries the unprocessed DoT upstream parameters; the
// consumer constructs the dot.Exchanger so option construction stays a
// pure data store.
type dotUpstreamSpec struct {
	addr netip.AddrPort
	tc   *tls.Config
}

// WithUpstream sets the Exchanger used to forward queries. The caller
// retains ownership of ex; the forwarder does not Close it. Use this
// when composing custom transports (DoH, DoQ, DNSCrypt, ...).
//
// Either WithUpstream, WithUDPUpstream, or WithDoTUpstream must be
// supplied; if more than one is provided the last one wins.
func WithUpstream(ex acidns.Exchanger) Option {
	return forwardOption{option.New(identUpstream{}, ex)}
}

// WithUDPUpstream forwards queries to addr over UDP, falling back to
// TCP automatically when the UDP response is truncated (TC=1) per
// RFC 1035 §4.2.1 and the standard stub-resolver convention.
func WithUDPUpstream(addr netip.AddrPort) Option {
	return forwardOption{option.New(identUDPUpstream{}, addr)}
}

// WithDoTUpstream forwards queries to addr over RFC 7858 DoT. Pass a
// fully-formed *tls.Config (custom roots, mTLS, KeyLogWriter, ...) to
// drive certificate verification — tc.ServerName is honored for SNI;
// when forwarding to an IP literal (e.g. "8.8.8.8:853") set
// tc.ServerName to the verifying name (e.g. "dns.google"). Pass nil to
// use the dot package defaults.
func WithDoTUpstream(addr netip.AddrPort, tc *tls.Config) Option {
	return forwardOption{option.New(identDoTUpstream{}, dotUpstreamSpec{addr: addr, tc: tc})}
}

// WithCacheSize sets the number of entries retained in the LRU cache.
// Defaults to 4096. A non-positive value disables caching.
func WithCacheSize(n int) Option {
	return forwardOption{option.New(identCacheSize{}, n)}
}

// WithMinTTL applies a floor to positive cached TTLs. A response whose
// records carry a smaller TTL is held for at least this long, smoothing
// over upstreams that advertise short TTLs to fight caching. Defaults
// to 0 (no floor).
func WithMinTTL(d time.Duration) Option {
	return forwardOption{option.New(identMinTTL{}, d)}
}

// WithMaxTTL caps positive cached TTLs at the given duration. Defaults
// to 24 hours, matching common stub-resolver behavior.
func WithMaxTTL(d time.Duration) Option {
	return forwardOption{option.New(identMaxTTL{}, d)}
}

// WithMaxNegativeTTL caps negative (NXDOMAIN / NoData) cache lifetimes
// at the given duration, applied on top of the SOA MINIMUM as required
// by RFC 2308 §5. Defaults to 5 minutes.
func WithMaxNegativeTTL(d time.Duration) Option {
	return forwardOption{option.New(identMaxNegTTL{}, d)}
}

// WithQueryTimeout sets the deadline applied to upstream Exchange calls
// when the inbound request's context has no deadline. Defaults to 5
// seconds.
func WithQueryTimeout(d time.Duration) Option {
	return forwardOption{option.New(identQueryTimeout{}, d)}
}

// WithMaxInflight caps the number of concurrent distinct upstream
// Exchange calls. Singleflight already coalesces concurrent requests
// for the same (qname, qtype, class, DO bit), so this cap bounds the
// pool of distinct upstream goroutines an attacker can pin by issuing
// a flood of distinct random qnames. Excess cache misses past the cap
// fail fast with [ErrInflightFull] (callers see SERVFAIL); the cap
// does NOT delay or queue. Defaults to 1024. A non-positive value
// disables the cap.
func WithMaxInflight(n int) Option {
	return forwardOption{option.New(identMaxInflight{}, n)}
}

// WithClock injects the clock used for cache freshness decisions.
// The default is [time.Now]. Tests pass a controllable clock to verify
// TTL expiry without sleeping in real time.
func WithClock(now func() time.Time) Option {
	return forwardOption{option.New(identClock{}, now)}
}

// WithLogger attaches a slog.Logger that the forwarder uses to emit one
// structured event per inbound query: "forward.serve" carrying the qname,
// qtype, decision (cache_hit / forwarded), upstream RCODE, and elapsed
// duration. Upstream errors are logged at error level with the wrapped
// cause; everything else is debug.
//
// The default is a no-op handler — passing nil restores the default.
func WithLogger(l *slog.Logger) Option {
	return forwardOption{option.New(identLogger{}, l)}
}

// WithAllowNoRD toggles the safe default of refusing inbound queries
// whose header has the Recursion Desired (RD) bit clear. A caching
// forwarder that answers RD=0 from cache is an open amplification
// source: any peer can elicit cached records without proving they
// wanted recursion, the same risk the recursive resolver closes by
// default.
//
// Default: refuse RD=0. Pass enable=true only when the forwarder is
// deployed inside a trust boundary where every peer is intentionally
// allowed to read the cache, and ideally only after gating the
// listener with an ACL. The bool form lets a layered config opt back
// in to the safe default after a profile enabled it.
func WithAllowNoRD(enable bool) Option {
	return forwardOption{option.New(identAllowNoRD{}, enable)}
}
