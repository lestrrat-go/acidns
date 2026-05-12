package acidns

// EDNS Cookies (RFC 7873 / RFC 9018) middleware.
//
// The cookies/ package supplies the Server primitive (mint + validate
// per-source server cookies); this middleware bridges that primitive
// onto the Handler interface so any Server framework user can opt in to
// cookie processing without re-implementing the state machine.
//
// Behaviour:
//
//   - Request has no DNS Cookie option: pass through to inner. The
//     response gets no cookie added. Many clients still don't send
//     cookies; rejecting them universally would be a regression.
//   - Request has only a client cookie (8 bytes): mint a fresh server
//     cookie, attach it to the response so the client cache can pick it
//     up. The response is otherwise unaltered.
//   - Request has client + server cookie and the server cookie is
//     valid: refresh the server cookie on the response (re-bind the
//     cookie to a current timestamp).
//   - Request has client + server cookie but the server cookie is
//     invalid (wrong HMAC, wrong source addr, outside the age window):
//     return BADCOOKIE per RFC 7873 §5.2.5 with a fresh server cookie
//     so the client can retry. Inner is NOT invoked — bad cookies are
//     a strong signal of spoofed sources or stale state, and not
//     letting them touch backend state is the whole point.

import (
	"context"
	"errors"
	"time"

	"github.com/lestrrat-go/acidns/cookies"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/option/v3"
)

// ErrNilCookieServer is returned by [NewCookies] when the supplied
// [cookies.Server] is nil. A nil server would NPE inside Validate/Make
// on the first request that carried a COOKIE option, and silently
// bypassing the middleware would surprise an operator who composed it
// expecting cookies to be enforced — so the constructor refuses at
// startup with a matchable sentinel.
var ErrNilCookieServer = errors.New("acidns: NewCookies requires a non-nil cookies.Server")

// CookieOption configures the cookies middleware.
type CookieOption interface {
	option.Interface
	cookieOption()
}

type cookieOption struct{ option.Interface }

func (cookieOption) cookieOption() {}

type cookieConfig struct {
	now              func() time.Time
	requireForLarge  bool
	largeRespMaxSize int
}

type identCookieClock struct{}
type identRequireCookieForLarge struct{}
type identRequireCookieMaxBytes struct{}

// WithCookieClock injects a custom clock. Test-only — production
// code should leave this unset and rely on time.Now.
func WithCookieClock(now func() time.Time) CookieOption {
	return cookieOption{option.New(identCookieClock{}, now)}
}

// WithRequireCookieForLargeResponse toggles RFC 7873 §1's
// amplification defence: an inbound UDP query that lacks a valid
// client/server cookie receives a TC=1 truncated reply when the inner
// handler's response would exceed the configured threshold, forcing
// the client to retry over TCP (where the 3-way handshake provides a
// path-validated channel that cannot be spoofed). TCP queries pass
// through unchanged.
//
// Default: enabled. Pass enable=false to disable on listeners where
// amplification is not a concern (e.g. localhost-only or LAN-only
// deployments). The threshold is set independently via
// [WithRequireCookieMaxBytes].
func WithRequireCookieForLargeResponse(enable bool) CookieOption {
	return cookieOption{option.New(identRequireCookieForLarge{}, enable)}
}

// WithRequireCookieMaxBytes sets the response-size threshold above
// which uncookied UDP queries get a TC=1 truncated reply (see
// [WithRequireCookieForLargeResponse]). Defaults to 1232 — the
// RFC 9715 EDNS UDP ceiling. Non-positive values reset to the
// default. Has no effect when the toggle is disabled.
func WithRequireCookieMaxBytes(maxBytes int) CookieOption {
	return cookieOption{option.New(identRequireCookieMaxBytes{}, maxBytes)}
}

// NewCookies wraps inner with EDNS-Cookie processing backed by srv.
// srv must outlive the returned Handler, and must be non-nil —
// otherwise [ErrNilCookieServer] is returned. See the package-level
// comment in middleware_cookies.go for the precise behavioural
// contract.
//
// The middleware does not _require_ cookies — clients that send no
// cookie option are passed through unchanged. To enforce cookies (e.g.
// only allow EDNS-Cookie clients to perform expensive lookups),
// compose this with a separate gate in front.
//
// # Spoofed BADCOOKIE amplification
//
// A BADCOOKIE reply is itself an EDNS-only response; its amplification
// factor against a query is roughly 1.0–1.5 and considerably below
// what a normal answer would offer to a spoofed source. If your
// deployment is exposed to internet-scale spoofed traffic, stack
// [NewRateLimit] in front of this middleware so the per-source token
// bucket bounds the BADCOOKIE emission rate before this layer ever
// runs. Cookies on a localhost-only or LAN-only listener do not
// benefit from the rate limit and need no extra layer.
func NewCookies(inner Handler, srv cookies.Server, opts ...CookieOption) (Handler, error) {
	if srv == nil {
		// A nil cookie server would NPE inside Validate/Make on the
		// first request that carried a COOKIE option. The middleware is
		// load-bearing for amplification defence (it gates large
		// responses on a validated cookie), so silently bypassing it
		// when srv is nil would surprise an operator who composed the
		// middleware expecting cookies to be enforced. Refuse at
		// construction — this is a programming error caught at startup.
		return nil, ErrNilCookieServer
	}
	c := cookieConfig{
		now:              time.Now,
		requireForLarge:  true,
		largeRespMaxSize: 1232,
	}
	for _, o := range opts {
		switch o.Ident() {
		case identCookieClock{}:
			c.now = option.MustGet[func() time.Time](o)
		case identRequireCookieForLarge{}:
			c.requireForLarge = option.MustGet[bool](o)
		case identRequireCookieMaxBytes{}:
			if v := option.MustGet[int](o); v > 0 {
				c.largeRespMaxSize = v
			}
		}
	}
	return &cookiesMW{
		inner:            inner,
		srv:              srv,
		now:              c.now,
		requireForLarge:  c.requireForLarge,
		largeRespMaxSize: c.largeRespMaxSize,
	}, nil
}

type cookiesMW struct {
	inner            Handler
	srv              cookies.Server
	now              func() time.Time
	requireForLarge  bool
	largeRespMaxSize int
}

func (m *cookiesMW) ServeDNS(ctx context.Context, w ResponseWriter, q wire.Message) {
	cc, sc, hasCookie := extractCookies(q)
	hasValidCookie := false
	if hasCookie {
		addr := w.RemoteAddr().Addr()
		now := m.now()

		if len(sc) >= 8 {
			if _, err := m.srv.Validate(sc, cc, addr, now); err != nil {
				// Invalid server cookie → BADCOOKIE response. Mint a fresh
				// one so the client can retry, and short-circuit the inner
				// handler entirely.
				//
				// LOAD-BEARING: this WriteMsg goes through whatever writer
				// the caller supplied, so when cookies is composed inside
				// RRL (the default in NewPublicUDPServer) BADCOOKIE replies
				// are counted against RRL's error-class budget. Do not
				// substitute a freshly-minted ResponseWriter or move
				// cookies outside RRL without re-establishing that path —
				// TestRRLGatesBADCOOKIEReplies pins the invariant.
				fresh := m.srv.Make(cc, addr, now)
				_ = w.WriteMsg(buildBadCookieResponse(q, cc, fresh))
				return
			}
			hasValidCookie = true
		}

		// Either client-only (first contact) or valid client+server: in
		// both cases mint a fresh server cookie and attach it to the
		// response.
		fresh := m.srv.Make(cc, addr, now)
		cw := &cookiesWriter{ResponseWriter: w, cc: cc, sc: fresh}
		// If the cookie is only client-side (first contact), the response
		// is not yet path-validated either — apply the large-response
		// gate just as if the request had no cookie option at all.
		if m.requireForLarge && !hasValidCookie && isUDPNetwork(w.Network()) {
			gw := &cookieSizeGate{ResponseWriter: cw, q: q, maxBytes: m.largeRespMaxSize}
			m.inner.ServeDNS(ctx, gw, q)
			return
		}
		m.inner.ServeDNS(ctx, cw, q)
		return
	}

	// No cookie option at all. Optionally apply the amplification gate.
	if m.requireForLarge && isUDPNetwork(w.Network()) {
		gw := &cookieSizeGate{ResponseWriter: w, q: q, maxBytes: m.largeRespMaxSize}
		m.inner.ServeDNS(ctx, gw, q)
		return
	}
	m.inner.ServeDNS(ctx, w, q)
}

// isUDPNetwork reports whether the writer's transport label denotes a
// UDP-shaped datagram protocol, where amplification defence applies.
// "udp" is the canonical label for the bundled UDP server; "dnscrypt"
// also runs over UDP and is included for the same reason. Stream
// transports (tcp, dot, doq) are 3-way-handshake validated and don't
// need this defence.
func isUDPNetwork(net string) bool {
	switch net {
	case "udp", "dnscrypt":
		return true
	}
	return false
}

// cookieSizeGate intercepts the inner handler's WriteMsg, measures the
// serialised response, and substitutes a TC=1 stub when the response
// exceeds the configured ceiling for cookieless UDP queries.
type cookieSizeGate struct {
	ResponseWriter

	q        wire.Message
	maxBytes int
	wrote    bool
}

func (g *cookieSizeGate) WriteMsg(m wire.Message) error {
	if g.wrote {
		return g.ResponseWriter.WriteMsg(m)
	}
	g.wrote = true
	buf, err := wire.Pack(m)
	if err == nil && len(buf) <= g.maxBytes {
		return g.ResponseWriter.WriteMsg(m)
	}
	return g.ResponseWriter.WriteMsg(truncateForCookieGate(m, g.q))
}

// truncateForCookieGate builds the slip reply for the
// large-response-without-cookie case: header + question, OPT echoed
// from the RESPONSE (NOT the request), TC=1 set, and AA/AD cleared
// because they no longer describe the stripped body. Mirrors the
// truncation logic in udpResponseWriter.WriteMsg so the gate's stub
// has the same EDNS shape (UDPSize, DO bit, extended RCODE) the
// underlying UDP writer would produce — otherwise an EDNS-aware
// client receives a TC=1 message whose advertised UDPSize is the
// REQUEST's UDPSize (e.g. 4096), which contradicts the operator's
// truncation policy.
func truncateForCookieGate(m wire.Message, q wire.Message) wire.Message {
	b := wire.NewMessageBuilder().
		ID(m.ID()).
		Flags(m.Flags().
			WithTruncated(true).
			WithResponse(true).
			WithAuthoritative(false).
			WithAuthenticData(false))
	if qs := m.Questions(); len(qs) > 0 {
		b = b.Question(qs[0])
	} else if qs := q.Questions(); len(qs) > 0 {
		b = b.Question(qs[0])
	}
	if e, ok := m.EDNS(); ok {
		b = b.EDNS(e)
	}
	out, err := b.Build()
	if err != nil {
		return m
	}
	return out
}

// cookiesWriter wraps the inner handler's writer and rewrites the
// outgoing response to include the freshly-minted server cookie in
// the OPT pseudo-RR. If the response already carries an OPT, its
// non-cookie options are preserved; an existing cookie option is
// replaced.
type cookiesWriter struct {
	ResponseWriter

	cc    [8]byte
	sc    []byte
	wrote bool
}

func (w *cookiesWriter) WriteMsg(m wire.Message) error {
	if w.wrote {
		return w.ResponseWriter.WriteMsg(m)
	}
	w.wrote = true
	return w.ResponseWriter.WriteMsg(attachCookieOption(m, w.cc, w.sc))
}

// extractCookies pulls the client cookie and (optional) server cookie
// out of q's EDNS options. Returns ok=false if the message has no
// EDNS, no Cookie option, or carries multiple Cookie OPTs (a malformed
// query per RFC 7873 §4 — a sender MUST send at most one Cookie
// option, so a second occurrence indicates either an attack or a
// broken peer; either way the safe default is to reject).
func extractCookies(q wire.Message) (cc [8]byte, sc []byte, ok bool) {
	edns, hasEDNS := q.EDNS()
	if !hasEDNS {
		return cc, nil, false
	}
	count := 0
	var firstC [8]byte
	var firstS []byte
	var firstValid bool
	for _, o := range edns.Options() {
		if o.Code() != wire.EDNSOptionCookie {
			continue
		}
		count++
		if count > 1 {
			return cc, nil, false
		}
		c, s, valid := wire.Cookies(o)
		firstC, firstS, firstValid = c, s, valid
	}
	if count == 1 && firstValid {
		return firstC, firstS, true
	}
	return cc, nil, false
}

// buildBadCookieResponse synthesises a BADCOOKIE reply per RFC 7873
// §5.2.5: extended RCODE = 23 (BADCOOKIE), with the freshly-minted
// server cookie attached so the client can retry.
func buildBadCookieResponse(q wire.Message, cc [8]byte, sc []byte) wire.Message {
	cookieOpt, _ := wire.NewClientServerCookie(cc, sc)
	const badCookie = 23
	// Echo the requestor's advertised UDP payload size when present.
	// Hardcoding 1232 here would push an off-path advertised size onto
	// clients that asked for a smaller envelope (and into operator
	// heuristics that key on the OPT UDPSize being whatever the client
	// negotiated).
	udpSize := uint16(1232)
	if e, ok := q.EDNS(); ok && e.UDPSize() != 0 {
		udpSize = e.UDPSize()
	}
	eb := wire.NewEDNSBuilder().
		UDPSize(udpSize).
		ExtendedRCODE(badCookie >> 4).
		Option(cookieOpt)

	ed, err := eb.Build()
	if err != nil {
		fb, _ := wire.NewMessageBuilder().Response(true).RCODE(wire.RCODEServFail).Build()
		return fb
	}
	b := wire.NewMessageBuilder().
		ID(q.ID()).
		Response(true).
		RecursionDesired(q.Flags().RecursionDesired()).
		RCODE(wire.RCODE(badCookie & 0x0f)).
		EDNS(ed)
	if qs := q.Questions(); len(qs) > 0 {
		b = b.Question(qs[0])
	}
	out, err := b.Build()
	if err != nil {
		fb, _ := wire.NewMessageBuilder().Response(true).RCODE(wire.RCODEServFail).Build()
		return fb
	}
	return out
}

// attachCookieOption returns m with a Cookie EDNS option attached to
// its OPT pseudo-RR. Existing OPT (with non-cookie options) is
// preserved; an existing cookie option is replaced. If m carried no
// OPT we still attach one — the response is now EDNS-cognisant.
func attachCookieOption(m wire.Message, cc [8]byte, sc []byte) wire.Message {
	cookieOpt, err := wire.NewClientServerCookie(cc, sc)
	if err != nil {
		return m
	}

	eb := wire.NewEDNSBuilder()
	if e, ok := m.EDNS(); ok {
		eb = eb.UDPSize(e.UDPSize()).
			Version(e.Version()).
			ExtendedRCODE(e.ExtendedRCODE()).
			DO(e.DO())
		for _, opt := range e.Options() {
			if opt.Code() == wire.EDNSOptionCookie {
				continue
			}
			eb = eb.Option(opt)
		}
	} else {
		eb = eb.UDPSize(1232)
	}
	eb = eb.Option(cookieOpt)

	ed, err := eb.Build()
	if err != nil {
		return m
	}
	b := wire.NewMessageBuilder().
		ID(m.ID()).
		Flags(m.Flags()).
		EDNS(ed)
	for _, q := range m.Questions() {
		b = b.Question(q)
	}
	for _, r := range m.Answers() {
		b = b.Answer(r)
	}
	for _, r := range m.Authorities() {
		b = b.Authority(r)
	}
	for _, r := range m.Additionals() {
		b = b.Additional(r)
	}
	out, err := b.Build()
	if err != nil {
		return m // fall back to the un-augmented response
	}
	return out
}
