package acidns

// Public-listener convenience wrappers.
//
// NewPublicUDPServer / NewPublicTCPServer bake in the recommended
// middleware stack for an internet-exposed listener so operators do
// not have to rediscover the layering. The stack, from outermost to
// innermost, is:
//
//   ACL (drop-denied)  ← outermost: cheapest filter, no work spent on
//                        sources that are categorically out-of-policy.
//   Rate limit          ← bounds per-source query budgets so a single
//                        peer cannot dominate the listener; runs before
//                        the cookie + RRL machinery so spoofed-source
//                        floods are clipped early. Per-source on its
//                        own is insufficient against spoofed sources;
//                        that's RRL's job below.
//   RRL                 ← bounds per-(source-prefix, response-name)
//                        amplification. Runs ahead of cookies so
//                        BADCOOKIE replies (which are themselves
//                        cookies-middleware output) are still subject
//                        to RRL's slip rate.
//   Cookies             ← RFC 7873 amplification gate: cookieless UDP
//                        responses that exceed the negotiated payload
//                        get TC=1, forcing TCP fallback. Innermost so
//                        upstream filters never see a request the
//                        cookies layer would have refused.
//   inner Handler       ← the operator-supplied application handler.
//
// Public-listener policy quirks:
//
//   - The ACL is required: an internet-exposed listener with no allow
//     list is almost certainly a misconfiguration (open resolver / open
//     authoritative). NewPublicUDPServer / NewPublicTCPServer return
//     [ErrPublicACLRequired] when the caller supplies no ACL options.
//   - The cookies middleware needs a [cookies.Server]; if one is not
//     supplied via [WithPublicCookiesServer], the wrapper builds an
//     in-process [cookies.MemorySecretPool] + [cookies.Server] with
//     defaults. The pool's Close is NOT wired here — callers that want
//     graceful rotation-goroutine shutdown must build the pool
//     themselves.
//
// To opt out of any single layer, build the stack manually and use
// [NewUDPServer] / [NewTCPServer] directly.

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/lestrrat-go/acidns/cookies"
)

// ErrPublicACLRequired is returned by [NewPublicUDPServer] /
// [NewPublicTCPServer] when no ACL options are supplied. A public
// listener with no allow list is silently allow-all and almost
// certainly a misconfiguration; refuse the construction so the
// operator notices immediately.
var ErrPublicACLRequired = errors.New("acidns: public listener requires at least one ACL option (use WithPublicACLOptions(WithACLAllow(...)))")

// PublicServerOption configures the public-listener wrappers.
type PublicServerOption interface {
	applyPublicServer(*publicServerConfig)
}

type publicServerOptionFunc func(*publicServerConfig)

func (f publicServerOptionFunc) applyPublicServer(c *publicServerConfig) { f(c) }

type publicServerConfig struct {
	aclOpts       []ACLOption
	rateLimitOpts []RateLimitOption
	rrlOpts       []RRLOption
	cookiesOpts   []CookieOption
	cookiesSrv    cookies.Server
	udpOpts       []UDPListenerOption
	tcpOpts       []TCPListenerOption
}

// WithPublicACLOptions threads ACL configuration through to the
// inner [NewACL] call. At least one of [WithACLAllow] /
// [WithACLDeny] MUST be supplied via this option, otherwise the
// public-listener constructor returns [ErrPublicACLRequired].
func WithPublicACLOptions(opts ...ACLOption) PublicServerOption {
	return publicServerOptionFunc(func(c *publicServerConfig) { c.aclOpts = append(c.aclOpts, opts...) })
}

// WithPublicRateLimitOptions threads per-source rate-limit
// configuration through to the inner [NewRateLimit] call.
func WithPublicRateLimitOptions(opts ...RateLimitOption) PublicServerOption {
	return publicServerOptionFunc(func(c *publicServerConfig) { c.rateLimitOpts = append(c.rateLimitOpts, opts...) })
}

// WithPublicRRLOptions threads response-rate-limit configuration
// through to the inner [NewRRL] call.
func WithPublicRRLOptions(opts ...RRLOption) PublicServerOption {
	return publicServerOptionFunc(func(c *publicServerConfig) { c.rrlOpts = append(c.rrlOpts, opts...) })
}

// WithPublicCookiesOptions threads cookies-middleware configuration
// through to the inner [NewCookies] call.
func WithPublicCookiesOptions(opts ...CookieOption) PublicServerOption {
	return publicServerOptionFunc(func(c *publicServerConfig) { c.cookiesOpts = append(c.cookiesOpts, opts...) })
}

// WithPublicCookiesServer supplies a pre-built [cookies.Server] to
// the cookies middleware. When unset, the wrapper builds an
// in-process secret pool and server with defaults. Supply a
// pre-built server when the secret pool needs a custom rotation
// cadence or shared lifetime with the calling process.
func WithPublicCookiesServer(srv cookies.Server) PublicServerOption {
	return publicServerOptionFunc(func(c *publicServerConfig) { c.cookiesSrv = srv })
}

// WithPublicUDPOptions threads UDP-listener configuration through
// to the inner [NewUDPServer] call.
func WithPublicUDPOptions(opts ...UDPListenerOption) PublicServerOption {
	return publicServerOptionFunc(func(c *publicServerConfig) { c.udpOpts = append(c.udpOpts, opts...) })
}

// WithPublicTCPOptions threads TCP-listener configuration through
// to the inner [NewTCPServer] call.
func WithPublicTCPOptions(opts ...TCPListenerOption) PublicServerOption {
	return publicServerOptionFunc(func(c *publicServerConfig) { c.tcpOpts = append(c.tcpOpts, opts...) })
}

// NewPublicUDPServer constructs a UDP server pre-wrapped with the
// recommended public-listener middleware stack: an ACL that drops
// denied queries silently (outermost), per-source rate limiting,
// RFC-style response rate limiting (RRL), and the cookies
// amplification gate (innermost). See the package-level comment in
// server_public.go for the rationale behind the layer ordering.
//
// At least one ACL option (typically [WithACLAllow]) MUST be supplied
// via [WithPublicACLOptions]; otherwise [ErrPublicACLRequired] is
// returned. The ACL is configured to drop denied queries silently
// ([WithACLDropDenied] true) — appropriate for an internet-exposed
// UDP listener where REFUSED replies would themselves be a small
// amplification primitive against spoofed sources.
//
// The cookies layer requires a [cookies.Server]; if none is supplied
// via [WithPublicCookiesServer], a fresh in-process secret pool +
// server is built with defaults.
func NewPublicUDPServer(addr netip.AddrPort, h Handler, opts ...PublicServerOption) (*UDPServer, error) {
	cfg := publicServerConfig{}
	for _, o := range opts {
		o.applyPublicServer(&cfg)
	}
	if len(cfg.aclOpts) == 0 {
		return nil, ErrPublicACLRequired
	}

	cookiesSrv, err := resolvePublicCookiesServer(cfg.cookiesSrv)
	if err != nil {
		return nil, err
	}

	// Build inside-out: cookies wraps the user handler, RRL wraps
	// cookies, rate limit wraps RRL, ACL wraps everything.
	stack := NewCookies(h, cookiesSrv, cfg.cookiesOpts...)
	stack = NewRRL(stack, cfg.rrlOpts...)
	stack = NewRateLimit(stack, cfg.rateLimitOpts...)
	aclOpts := append([]ACLOption{WithACLDropDenied(true)}, cfg.aclOpts...)
	stack, err = NewACL(stack, aclOpts...)
	if err != nil {
		return nil, fmt.Errorf("acidns: public udp server: %w", err)
	}

	srv, err := NewUDPServer(addr, stack, cfg.udpOpts...)
	if err != nil {
		return nil, fmt.Errorf("acidns: public udp server: %w", err)
	}
	return srv, nil
}

// NewPublicTCPServer constructs a TCP server pre-wrapped with the
// recommended public-listener middleware stack. The layering is
// identical to [NewPublicUDPServer]; the cookies amplification gate
// is a no-op on TCP (path-validated by the 3-way handshake) but
// remains in the stack so a single Handler can be shared between a
// UDP and a TCP listener with consistent behaviour.
//
// As with [NewPublicUDPServer], at least one ACL option MUST be
// supplied via [WithPublicACLOptions]; otherwise
// [ErrPublicACLRequired] is returned.
func NewPublicTCPServer(addr netip.AddrPort, h Handler, opts ...PublicServerOption) (*TCPServer, error) {
	cfg := publicServerConfig{}
	for _, o := range opts {
		o.applyPublicServer(&cfg)
	}
	if len(cfg.aclOpts) == 0 {
		return nil, ErrPublicACLRequired
	}

	cookiesSrv, err := resolvePublicCookiesServer(cfg.cookiesSrv)
	if err != nil {
		return nil, err
	}

	stack := NewCookies(h, cookiesSrv, cfg.cookiesOpts...)
	stack = NewRRL(stack, cfg.rrlOpts...)
	stack = NewRateLimit(stack, cfg.rateLimitOpts...)
	aclOpts := append([]ACLOption{WithACLDropDenied(true)}, cfg.aclOpts...)
	stack, err = NewACL(stack, aclOpts...)
	if err != nil {
		return nil, fmt.Errorf("acidns: public tcp server: %w", err)
	}

	srv, err := NewTCPServer(addr, stack, cfg.tcpOpts...)
	if err != nil {
		return nil, fmt.Errorf("acidns: public tcp server: %w", err)
	}
	return srv, nil
}

func resolvePublicCookiesServer(srv cookies.Server) (cookies.Server, error) {
	if srv != nil {
		return srv, nil
	}
	pool, err := cookies.NewSecretPool()
	if err != nil {
		return nil, fmt.Errorf("acidns: public listener: cookies pool: %w", err)
	}
	out, err := cookies.NewServer(pool)
	if err != nil {
		return nil, fmt.Errorf("acidns: public listener: cookies server: %w", err)
	}
	return out, nil
}
