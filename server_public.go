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
//   - The cookies middleware is required and the caller MUST supply a
//     [cookies.Server] via [WithPublicCookiesServer]. An in-process
//     [cookies.MemorySecretPool] with no rotation is not a safe
//     default for an internet-exposed listener — HMAC secrets would
//     never roll for the lifetime of the process, making cached
//     server cookies indistinguishable from long-lived shared
//     credentials. The constructor returns
//     [ErrPublicCookiesServerRequired] when no server is supplied.
//     Build the pool with [cookies.WithPoolContext] paired with
//     [cookies.WithPoolRotateEvery] (or pass a pre-rotated pool from
//     elsewhere in the process) and feed it to [cookies.NewServer].
//
// To opt out of any single layer, build the stack manually and use
// [NewUDPServer] / [NewTCPServer] directly.

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/lestrrat-go/acidns/cookies"
	"github.com/lestrrat-go/option/v3"
)

// ErrPublicACLRequired is returned by [NewPublicUDPServer] /
// [NewPublicTCPServer] when no ACL options are supplied. A public
// listener with no allow list is silently allow-all and almost
// certainly a misconfiguration; refuse the construction so the
// operator notices immediately.
var ErrPublicACLRequired = errors.New("acidns: public listener requires at least one ACL option (use WithPublicACLOptions(WithACLAllow(...)))")

// ErrPublicCookiesServerRequired is returned by [NewPublicUDPServer]
// / [NewPublicTCPServer] when no [cookies.Server] is supplied via
// [WithPublicCookiesServer]. The wrappers refuse to synthesise a
// default pool: a process-lifetime non-rotating HMAC secret is not a
// safe default for an internet-exposed listener. Build the pool with
// [cookies.NewSecretPool] (typically with [cookies.WithPoolContext]
// + [cookies.WithPoolRotateEvery]) and pass the resulting server in
// explicitly.
var ErrPublicCookiesServerRequired = errors.New("acidns: public listener requires an explicit cookies server (use WithPublicCookiesServer with a rotating cookies.SecretPool)")

// PublicServerOption configures the public-listener wrappers.
type PublicServerOption interface {
	option.Interface
	publicServerOption()
}

type publicServerOption struct{ option.Interface }

func (publicServerOption) publicServerOption() {}

type publicServerConfig struct {
	aclOpts       []ACLOption
	rateLimitOpts []RateLimitOption
	rrlOpts       []RRLOption
	cookiesOpts   []CookieOption
	cookiesSrv    cookies.Server
	udpOpts       []UDPListenerOption
	tcpOpts       []TCPListenerOption
}

type identPublicACLOptions struct{}
type identPublicRateLimitOptions struct{}
type identPublicRRLOptions struct{}
type identPublicCookiesOptions struct{}
type identPublicCookiesServer struct{}
type identPublicUDPOptions struct{}
type identPublicTCPOptions struct{}

// WithPublicACLOptions threads ACL configuration through to the
// inner [NewACL] call. At least one of [WithACLAllow] /
// [WithACLDeny] MUST be supplied via this option, otherwise the
// public-listener constructor returns [ErrPublicACLRequired].
func WithPublicACLOptions(opts ...ACLOption) PublicServerOption {
	return publicServerOption{option.New(identPublicACLOptions{}, opts)}
}

// WithPublicRateLimitOptions threads per-source rate-limit
// configuration through to the inner [NewRateLimit] call.
func WithPublicRateLimitOptions(opts ...RateLimitOption) PublicServerOption {
	return publicServerOption{option.New(identPublicRateLimitOptions{}, opts)}
}

// WithPublicRRLOptions threads response-rate-limit configuration
// through to the inner [NewRRL] call.
func WithPublicRRLOptions(opts ...RRLOption) PublicServerOption {
	return publicServerOption{option.New(identPublicRRLOptions{}, opts)}
}

// WithPublicCookiesOptions threads cookies-middleware configuration
// through to the inner [NewCookies] call.
func WithPublicCookiesOptions(opts ...CookieOption) PublicServerOption {
	return publicServerOption{option.New(identPublicCookiesOptions{}, opts)}
}

// WithPublicCookiesServer supplies the [cookies.Server] backing the
// public listener's cookies middleware. This option is REQUIRED —
// the public-listener constructors return
// [ErrPublicCookiesServerRequired] when it is missing, because
// silently spinning up an in-process pool with no rotation is not a
// safe default for an internet-exposed listener. Build the pool with
// [cookies.NewSecretPool] (typically with [cookies.WithPoolContext]
// + [cookies.WithPoolRotateEvery]) and wrap it with
// [cookies.NewServer].
func WithPublicCookiesServer(srv cookies.Server) PublicServerOption {
	return publicServerOption{option.New(identPublicCookiesServer{}, srv)}
}

// WithPublicUDPOptions threads UDP-listener configuration through
// to the inner [NewUDPServer] call.
func WithPublicUDPOptions(opts ...UDPListenerOption) PublicServerOption {
	return publicServerOption{option.New(identPublicUDPOptions{}, opts)}
}

// WithPublicTCPOptions threads TCP-listener configuration through
// to the inner [NewTCPServer] call.
func WithPublicTCPOptions(opts ...TCPListenerOption) PublicServerOption {
	return publicServerOption{option.New(identPublicTCPOptions{}, opts)}
}

// applyPublicOptions parses opts into cfg, shared between
// NewPublicUDPServer and NewPublicTCPServer.
func applyPublicOptions(opts []PublicServerOption) publicServerConfig {
	var cfg publicServerConfig
	for _, o := range opts {
		switch o.Ident() {
		case identPublicACLOptions{}:
			cfg.aclOpts = append(cfg.aclOpts, option.MustGet[[]ACLOption](o)...)
		case identPublicRateLimitOptions{}:
			cfg.rateLimitOpts = append(cfg.rateLimitOpts, option.MustGet[[]RateLimitOption](o)...)
		case identPublicRRLOptions{}:
			cfg.rrlOpts = append(cfg.rrlOpts, option.MustGet[[]RRLOption](o)...)
		case identPublicCookiesOptions{}:
			cfg.cookiesOpts = append(cfg.cookiesOpts, option.MustGet[[]CookieOption](o)...)
		case identPublicCookiesServer{}:
			cfg.cookiesSrv = option.MustGet[cookies.Server](o)
		case identPublicUDPOptions{}:
			cfg.udpOpts = append(cfg.udpOpts, option.MustGet[[]UDPListenerOption](o)...)
		case identPublicTCPOptions{}:
			cfg.tcpOpts = append(cfg.tcpOpts, option.MustGet[[]TCPListenerOption](o)...)
		}
	}
	return cfg
}

// buildPublicStack validates the public-listener preconditions and
// composes the middleware stack shared by [NewPublicUDPServer] and
// [NewPublicTCPServer]. Extracted so the composition order — Cookies
// (innermost) → RRL → RateLimit → ACL (outermost) — lives in exactly
// one place; the BADCOOKIE-through-RRL invariant pinned by
// TestRRLGatesBADCOOKIEReplies depends on cookies being inside RRL,
// and a silent drift between the UDP and TCP constructors would weaken
// one transport's security posture without failing tests.
//
// Validation sentinels ([ErrPublicACLRequired],
// [ErrPublicCookiesServerRequired]) are returned unwrapped so callers
// keep matching them with [errors.Is]; builder errors from
// [NewCookies] / [NewACL] propagate unwrapped and the caller adds the
// per-transport prefix via wrapPublicErr.
func buildPublicStack(h Handler, cfg publicServerConfig) (Handler, error) {
	if len(cfg.aclOpts) == 0 {
		return nil, ErrPublicACLRequired
	}
	if cfg.cookiesSrv == nil {
		return nil, ErrPublicCookiesServerRequired
	}
	stack, err := NewCookies(h, cfg.cookiesSrv, cfg.cookiesOpts...)
	if err != nil {
		return nil, err
	}
	stack = NewRRL(stack, cfg.rrlOpts...)
	stack = NewRateLimit(stack, cfg.rateLimitOpts...)
	aclOpts := append([]ACLOption{WithACLDropDenied(true)}, cfg.aclOpts...)
	stack, err = NewACL(stack, aclOpts...)
	if err != nil {
		return nil, err
	}
	return stack, nil
}

// wrapPublicErr applies the per-transport error prefix to errors from
// buildPublicStack while leaving the two public validation sentinels
// unwrapped — keeps the existing errors.Is(err, ErrPublicACLRequired)
// /ErrPublicCookiesServerRequired call sites matching on the byte-
// identical error string.
func wrapPublicErr(transport string, err error) error {
	if errors.Is(err, ErrPublicACLRequired) || errors.Is(err, ErrPublicCookiesServerRequired) {
		return err
	}
	return fmt.Errorf("acidns: public %s server: %w", transport, err)
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
// The cookies layer requires a [cookies.Server]; the caller MUST
// supply one via [WithPublicCookiesServer]. The wrapper deliberately
// refuses to synthesise a default in-process secret pool because a
// non-rotating HMAC secret pinned for the process lifetime is unsafe
// on a public listener; [ErrPublicCookiesServerRequired] is returned
// when the option is missing.
func NewPublicUDPServer(addr netip.AddrPort, h Handler, opts ...PublicServerOption) (*UDPServer, error) {
	cfg := applyPublicOptions(opts)
	stack, err := buildPublicStack(h, cfg)
	if err != nil {
		return nil, wrapPublicErr("udp", err)
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
// [ErrPublicACLRequired] is returned. A [cookies.Server] MUST be
// supplied via [WithPublicCookiesServer]; otherwise
// [ErrPublicCookiesServerRequired] is returned.
func NewPublicTCPServer(addr netip.AddrPort, h Handler, opts ...PublicServerOption) (*TCPServer, error) {
	cfg := applyPublicOptions(opts)
	stack, err := buildPublicStack(h, cfg)
	if err != nil {
		return nil, wrapPublicErr("tcp", err)
	}
	srv, err := NewTCPServer(addr, stack, cfg.tcpOpts...)
	if err != nil {
		return nil, fmt.Errorf("acidns: public tcp server: %w", err)
	}
	return srv, nil
}
