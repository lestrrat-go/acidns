package acidns_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/cookies"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

type cookieWriter struct {
	src      netip.AddrPort
	captured wire.Message
	written  bool
}

func (w *cookieWriter) WriteMsg(m wire.Message) error {
	w.captured = m
	w.written = true
	return nil
}
func (w *cookieWriter) RemoteAddr() netip.AddrPort { return w.src }
func (*cookieWriter) LocalAddr() netip.AddrPort    { return netip.AddrPort{} }
func (*cookieWriter) Network() string              { return netUDP }

func cookieMkInner() acidns.Handler {
	return acidns.HandlerFunc(func(_ context.Context, w acidns.ResponseWriter, q wire.Message) {
		ans := wire.NewRecord(q.Questions()[0].Name(), 60*time.Second,
			rdata.NewA(netip.MustParseAddr("203.0.113.99")))
		resp, _ := wire.NewBuilder().
			ID(q.ID()).
			Response(true).
			Question(q.Questions()[0]).
			Answer(ans).
			Build()
		_ = w.WriteMsg(resp)
	})
}

func newCookiesServer(t *testing.T) cookies.Server {
	t.Helper()
	pool, _ := cookies.NewSecretPool() // no auto-rotation in tests
	t.Cleanup(pool.Close)
	return cookies.NewServer(pool)
}

func extractCookieOpt(t *testing.T, m wire.Message) ([8]byte, []byte) {
	t.Helper()
	e, ok := m.EDNS()
	require.True(t, ok, "response must carry EDNS for cookie tests")
	for _, o := range e.Options() {
		if o.Code() != wire.EDNSOptionCookie {
			continue
		}
		cc, sc, ok := wire.Cookies(o)
		require.True(t, ok)
		return cc, sc
	}
	t.Fatalf("no cookie option in response")
	return [8]byte{}, nil
}

func TestCookiesPassThroughForNonCookieClient(t *testing.T) {
	t.Parallel()
	srv := newCookiesServer(t)
	h := acidns.NewCookies(cookieMkInner(), srv)

	q, err := wire.NewBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	require.NoError(t, err)

	w := &cookieWriter{src: netip.MustParseAddrPort("198.51.100.1:1")}
	h.ServeDNS(context.Background(), w, q)
	require.True(t, w.written)
	_, hasEDNS := w.captured.EDNS()
	require.False(t, hasEDNS,
		"non-cookie query must not get an OPT added by the cookies middleware")
}

func TestCookiesAttachesServerCookieOnFirstContact(t *testing.T) {
	t.Parallel()
	srv := newCookiesServer(t)
	h := acidns.NewCookies(cookieMkInner(), srv)

	cc := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	clientOpt := wire.NewClientCookie(cc)
	q, err := wire.NewBuilder().
		ID(2).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		EDNS(wire.NewEDNSBuilder().Option(clientOpt).Build()).
		Build()
	require.NoError(t, err)

	w := &cookieWriter{src: netip.MustParseAddrPort("198.51.100.2:1")}
	h.ServeDNS(context.Background(), w, q)

	gotCC, gotSC := extractCookieOpt(t, w.captured)
	require.Equal(t, cc, gotCC, "server must echo the client cookie")
	require.Len(t, gotSC, 16, "RFC 9018 server cookie is 16 bytes")
}

func TestCookiesAcceptsValidServerCookie(t *testing.T) {
	t.Parallel()
	srv := newCookiesServer(t)
	h := acidns.NewCookies(cookieMkInner(), srv)
	addr := netip.MustParseAddr("198.51.100.3")

	cc := [8]byte{9, 9, 9, 9, 9, 9, 9, 9}
	now := time.Now()
	sc := srv.Make(cc, addr, now)
	cookieOpt, err := wire.NewClientServerCookie(cc, sc)
	require.NoError(t, err)

	q, err := wire.NewBuilder().
		ID(3).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		EDNS(wire.NewEDNSBuilder().Option(cookieOpt).Build()).
		Build()
	require.NoError(t, err)

	w := &cookieWriter{src: netip.AddrPortFrom(addr, 1)}
	h.ServeDNS(context.Background(), w, q)

	require.Equal(t, wire.RCODENoError, w.captured.Flags().RCODE())
	require.Equal(t, 1, len(w.captured.Answers()), "valid cookie must reach inner handler")
}

func TestCookiesRejectsInvalidServerCookieWithBADCOOKIE(t *testing.T) {
	t.Parallel()
	srv := newCookiesServer(t)
	innerCalled := false
	h := acidns.NewCookies(acidns.HandlerFunc(func(ctx context.Context, w acidns.ResponseWriter, q wire.Message) {
		innerCalled = true
		cookieMkInner().ServeDNS(ctx, w, q)
	}), srv)

	cc := [8]byte{1, 1, 1, 1, 1, 1, 1, 1}
	// Forge a 16-byte server cookie that won't validate.
	bogus := make([]byte, 16)
	bogus[0] = 1
	cookieOpt, err := wire.NewClientServerCookie(cc, bogus)
	require.NoError(t, err)

	q, err := wire.NewBuilder().
		ID(4).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		EDNS(wire.NewEDNSBuilder().Option(cookieOpt).Build()).
		Build()
	require.NoError(t, err)

	w := &cookieWriter{src: netip.MustParseAddrPort("198.51.100.4:1")}
	h.ServeDNS(context.Background(), w, q)

	// BADCOOKIE = 23 = (1 << 4) | 7, so header RCODE = 7 (YXRRSet).
	require.Equal(t, wire.RCODE(7), w.captured.Flags().RCODE())
	e, ok := w.captured.EDNS()
	require.True(t, ok)
	require.Equal(t, uint8(1), e.ExtendedRCODE(),
		"BADCOOKIE = extended-RCODE 1 << 4 | header 7")
	require.False(t, innerCalled,
		"bad-cookie request must short-circuit before the inner handler")

	// And we must still ship a fresh server cookie so the client can retry.
	gotCC, gotSC := extractCookieOpt(t, w.captured)
	require.Equal(t, cc, gotCC)
	require.Len(t, gotSC, 16)
}
