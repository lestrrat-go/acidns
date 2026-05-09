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
	"time"

	"github.com/lestrrat-go/acidns/cookies"
	"github.com/lestrrat-go/acidns/wire"
)

// CookieOption configures the cookies middleware.
type CookieOption interface{ applyCookies(*cookieConfig) }

type cookieOptionFunc func(*cookieConfig)

func (f cookieOptionFunc) applyCookies(c *cookieConfig) { f(c) }

type cookieConfig struct {
	now func() time.Time
}

// WithClock injects a custom clock. Test-only — production code
// should leave this unset and rely on time.Now.
func WithClock(now func() time.Time) CookieOption {
	return cookieOptionFunc(func(c *cookieConfig) { c.now = now })
}

// NewCookies wraps inner with EDNS-Cookie processing backed by srv.
// srv must outlive the returned Handler. See the package-level comment
// in middleware_cookies.go for the precise behavioural contract.
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
func NewCookies(inner Handler, srv cookies.Server, opts ...CookieOption) Handler {
	c := cookieConfig{now: time.Now}
	for _, o := range opts {
		o.applyCookies(&c)
	}
	return &cookiesMW{inner: inner, srv: srv, now: c.now}
}

type cookiesMW struct {
	inner Handler
	srv   cookies.Server
	now   func() time.Time
}

func (m *cookiesMW) ServeDNS(ctx context.Context, w ResponseWriter, q wire.Message) {
	cc, sc, hasCookie := extractCookies(q)
	if !hasCookie {
		m.inner.ServeDNS(ctx, w, q)
		return
	}

	addr := w.RemoteAddr().Addr()
	now := m.now()

	if len(sc) >= 8 {
		if _, err := m.srv.Validate(sc, cc, addr, now); err != nil {
			// Invalid server cookie → BADCOOKIE response. Mint a fresh
			// one so the client can retry, and short-circuit the inner
			// handler entirely.
			fresh := m.srv.Make(cc, addr, now)
			_ = w.WriteMsg(buildBadCookieResponse(q, cc, fresh))
			return
		}
	}

	// Either client-only (first contact) or valid client+server: in
	// both cases mint a fresh server cookie and attach it to the
	// response.
	fresh := m.srv.Make(cc, addr, now)
	cw := &cookiesWriter{ResponseWriter: w, cc: cc, sc: fresh}
	m.inner.ServeDNS(ctx, cw, q)
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
// EDNS or no Cookie option.
func extractCookies(q wire.Message) (cc [8]byte, sc []byte, ok bool) {
	edns, hasEDNS := q.EDNS()
	if !hasEDNS || edns == nil {
		return cc, nil, false
	}
	for _, o := range edns.Options() {
		if o.Code() != wire.EDNSOptionCookie {
			continue
		}
		c, s, valid := wire.Cookies(o)
		if !valid {
			continue
		}
		return c, s, true
	}
	return cc, nil, false
}

// buildBadCookieResponse synthesises a BADCOOKIE reply per RFC 7873
// §5.2.5: extended RCODE = 23 (BADCOOKIE), with the freshly-minted
// server cookie attached so the client can retry.
func buildBadCookieResponse(q wire.Message, cc [8]byte, sc []byte) wire.Message {
	cookieOpt, _ := wire.NewClientServerCookie(cc, sc)
	const badCookie = 23
	eb := wire.NewEDNSBuilder().
		UDPSize(1232).
		ExtendedRCODE(badCookie >> 4).
		Option(cookieOpt)

	ed, err := eb.Build()
	if err != nil {
		fb, _ := wire.NewBuilder().Response(true).RCODE(wire.RCODEServFail).Build()
		return fb
	}
	b := wire.NewBuilder().
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
		fb, _ := wire.NewBuilder().Response(true).RCODE(wire.RCODEServFail).Build()
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
	if e, ok := m.EDNS(); ok && e != nil {
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
	b := wire.NewBuilder().
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
