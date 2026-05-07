package forward

import (
	"crypto/tls"
	"net/netip"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/dot"
)

// Option configures a forward Handler.
type Option interface {
	applyForward(*config)
}

type optionFunc func(*config)

func (f optionFunc) applyForward(c *config) { f(c) }

type config struct {
	upstream     acidns.Exchanger
	upstreamName string
	cacheSize    int
	minTTL       time.Duration
	maxTTL       time.Duration
	maxNegTTL    time.Duration
	queryTimeout time.Duration
	now          func() time.Time
}

// WithUpstream sets the Exchanger used to forward queries. The caller
// retains ownership of ex; the forwarder does not Close it. Use this
// when composing custom transports (DoH, DoQ, DNSCrypt, ...).
//
// Either WithUpstream, WithUDPUpstream, or WithDoTUpstream must be
// supplied; if more than one is provided the last one wins.
func WithUpstream(ex acidns.Exchanger) Option {
	return optionFunc(func(c *config) {
		c.upstream = ex
		c.upstreamName = "(custom)"
	})
}

// WithUDPUpstream forwards queries to addr over UDP, falling back to
// TCP automatically when the UDP response is truncated (TC=1) per
// RFC 1035 §4.2.1 and the standard stub-resolver convention.
func WithUDPUpstream(addr netip.AddrPort) Option {
	return optionFunc(func(c *config) {
		c.upstream = newUDPTCPFallback(addr)
		c.upstreamName = addr.String()
	})
}

// WithDoTUpstream forwards queries to addr over RFC 7858 DoT. If
// serverName is empty, the address's hostname is used for SNI /
// certificate verification; pass an explicit name when forwarding to
// an IP literal (e.g. "8.8.8.8:853" with serverName "dns.google").
func WithDoTUpstream(addr netip.AddrPort, serverName string) Option {
	return optionFunc(func(c *config) {
		ex, err := dot.New(addr, dot.WithServerName(serverName))
		if err != nil {
			c.upstream = errExchanger{err: err}
			c.upstreamName = "(invalid dot)"
			return
		}
		c.upstream = ex
		c.upstreamName = "tls://" + addr.String()
	})
}

// WithDoTUpstreamTLSConfig is like WithDoTUpstream but lets the caller
// supply a fully-formed *tls.Config (custom roots, mTLS, KeyLogWriter,
// etc.). serverName from tc.ServerName is honored.
func WithDoTUpstreamTLSConfig(addr netip.AddrPort, tc *tls.Config) Option {
	return optionFunc(func(c *config) {
		ex, err := dot.New(addr, dot.WithTLSConfig(tc))
		if err != nil {
			c.upstream = errExchanger{err: err}
			c.upstreamName = "(invalid dot)"
			return
		}
		c.upstream = ex
		c.upstreamName = "tls://" + addr.String()
	})
}

// WithCacheSize sets the number of entries retained in the LRU cache.
// Defaults to 4096. A non-positive value disables caching.
func WithCacheSize(n int) Option {
	return optionFunc(func(c *config) { c.cacheSize = n })
}

// WithMinTTL applies a floor to positive cached TTLs. A response whose
// records carry a smaller TTL is held for at least this long, smoothing
// over upstreams that advertise short TTLs to fight caching. Defaults
// to 0 (no floor).
func WithMinTTL(d time.Duration) Option {
	return optionFunc(func(c *config) { c.minTTL = d })
}

// WithMaxTTL caps positive cached TTLs at the given duration. Defaults
// to 24 hours, matching common stub-resolver behavior.
func WithMaxTTL(d time.Duration) Option {
	return optionFunc(func(c *config) { c.maxTTL = d })
}

// WithMaxNegativeTTL caps negative (NXDOMAIN / NoData) cache lifetimes
// at the given duration, applied on top of the SOA MINIMUM as required
// by RFC 2308 §5. Defaults to 5 minutes.
func WithMaxNegativeTTL(d time.Duration) Option {
	return optionFunc(func(c *config) { c.maxNegTTL = d })
}

// WithQueryTimeout sets the deadline applied to upstream Exchange calls
// when the inbound request's context has no deadline. Defaults to 5
// seconds.
func WithQueryTimeout(d time.Duration) Option {
	return optionFunc(func(c *config) { c.queryTimeout = d })
}

// WithNowFunc injects the clock used for cache freshness decisions.
// The default is [time.Now]. Tests pass a controllable clock to verify
// TTL expiry without sleeping in real time.
func WithNowFunc(now func() time.Time) Option {
	return optionFunc(func(c *config) { c.now = now })
}
