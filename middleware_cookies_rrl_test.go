package acidns_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// TestRRLGatesBADCOOKIEReplies pins the load-bearing invariant in the
// public-server stack: BADCOOKIE replies emitted by the cookies
// middleware flow through the outer RRL writer wrapper, so they are
// counted against the error-class budget and slip/drop along with
// SERVFAIL/REFUSED. The invariant exists only because cookies
// happens to be composed inside RRL AND emits BADCOOKIE via the
// writer it received. A refactor that mints a fresh writer for
// BADCOOKIE, or moves cookies outside RRL, would silently restore
// the amplification surface.
func TestRRLGatesBADCOOKIEReplies(t *testing.T) {
	t.Parallel()
	srv := newCookiesServer(t)
	cookiesMW, err := acidns.NewCookies(cookieMkInner(), srv)
	require.NoError(t, err)

	const burst = 3
	stack := acidns.NewRRL(cookiesMW,
		acidns.WithRRLErrorQPS(0.0001), // effectively no refill
		acidns.WithRRLBurst(burst),
		acidns.WithRRLSlipRate(0), // drop on overage so we can count
	)

	cc := [8]byte{1, 1, 1, 1, 1, 1, 1, 1}
	bogus := make([]byte, 16) // 16-byte invalid server cookie
	bogus[0] = 1
	cookieOpt, err := wire.NewClientServerCookie(cc, bogus)
	require.NoError(t, err)

	src := netip.MustParseAddrPort("198.51.100.55:1")
	const total = burst + 5
	passed := 0
	for i := range total {
		q, qerr := wire.NewMessageBuilder().
			ID(uint16(i + 1)).
			Question(wire.NewQuestion(wire.MustParseName("victim.example."), rrtype.A)).
			EDNS(mustEDNS(t, wire.NewEDNSBuilder().Option(cookieOpt))).
			Build()
		require.NoError(t, qerr)

		w := &cookieWriter{src: src}
		stack.ServeDNS(context.Background(), w, q)
		if !w.written {
			continue
		}
		passed++
		// What passed must actually be BADCOOKIE — header RCODE 7
		// (low nibble of 23) + extended-RCODE 1 (high nibble).
		require.Equal(t, wire.RCODE(7), w.captured.Flags().RCODE())
		e, ok := w.captured.EDNS()
		require.True(t, ok)
		require.Equal(t, uint8(1), e.ExtendedRCODE())
	}
	require.Equal(t, burst, passed,
		"BADCOOKIE replies must be gated by RRL when cookies is composed "+
			"inside RRL (the public-server layering). %d bad-cookie queries "+
			"fired from one source, %d passed; expected exactly the burst "+
			"(%d). passed > burst means cookies' WriteMsg never reached "+
			"rrlWriter (cookies moved outside RRL?). passed < burst means "+
			"cookies routed the BADCOOKIE somewhere other than the writer "+
			"it was given.",
		total, passed, burst)
}
