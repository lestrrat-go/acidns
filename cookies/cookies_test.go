package cookies_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/cookies"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/stretchr/testify/require"
)

func TestServerCookieRoundTrip(t *testing.T) {
	t.Parallel()
	pool, _ := cookies.NewSecretPool()
	t.Cleanup(pool.Close)
	srv := cookies.NewServer(pool)
	cc := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	addr := netip.MustParseAddr("203.0.113.1")
	now := time.Unix(1_700_000_000, 0).UTC()

	cookie := srv.Make(cc, addr, now)
	require.Len(t, cookie, 16)

	ts, err := srv.Validate(cookie, cc, addr, now)
	require.NoError(t, err)
	require.Equal(t, now.Unix(), ts.Unix())
}

func TestServerCookieRejectsWrongAddr(t *testing.T) {
	t.Parallel()
	pool, _ := cookies.NewSecretPool()
	t.Cleanup(pool.Close)
	srv := cookies.NewServer(pool)
	cc := [8]byte{0xab, 0xcd, 0xef, 1, 2, 3, 4, 5}
	now := time.Unix(1_700_000_000, 0).UTC()

	cookie := srv.Make(cc, netip.MustParseAddr("203.0.113.1"), now)
	_, err := srv.Validate(cookie, cc, netip.MustParseAddr("203.0.113.2"), now)
	require.ErrorIs(t, err, cookies.ErrCookieMismatch)
}

func TestServerCookieRejectsExpired(t *testing.T) {
	t.Parallel()
	pool, _ := cookies.NewSecretPool()
	t.Cleanup(pool.Close)
	srv := cookies.NewServer(pool, cookies.WithServerMaxAge(30*time.Minute))
	cc := [8]byte{}
	addr := netip.MustParseAddr("203.0.113.1")
	now := time.Unix(1_700_000_000, 0).UTC()
	cookie := srv.Make(cc, addr, now)

	// 31 minutes later → outside acceptance window.
	_, err := srv.Validate(cookie, cc, addr, now.Add(31*time.Minute))
	require.ErrorIs(t, err, cookies.ErrCookieExpired)
}

func TestServerCookieAcceptsPreviousSecretAfterRotation(t *testing.T) {
	t.Parallel()
	pool, _ := cookies.NewSecretPool()
	t.Cleanup(pool.Close)
	srv := cookies.NewServer(pool)
	cc := [8]byte{42, 42, 42, 42, 42, 42, 42, 42}
	addr := netip.MustParseAddr("198.51.100.5")
	now := time.Now().UTC().Truncate(time.Second)

	cookie := srv.Make(cc, addr, now)
	require.NoError(t, pool.Rotate())
	// After rotation the OLD secret is "previous"; validation must still
	// succeed because Server.All returns both.
	_, err := srv.Validate(cookie, cc, addr, now.Add(time.Minute))
	require.NoError(t, err)

	// After two rotations the OLD secret is gone → fail.
	require.NoError(t, pool.Rotate())
	_, err = srv.Validate(cookie, cc, addr, now.Add(2*time.Minute))
	require.ErrorIs(t, err, cookies.ErrCookieMismatch)
}

func TestClientApplyAndObserveAndRetry(t *testing.T) {
	t.Parallel()
	c := cookies.NewClient()
	server := netip.MustParseAddrPort("198.51.100.10:53")

	// Apply on a fresh server emits a client-only cookie.
	b := wire.NewEDNSBuilder()
	b = c.Apply(server, b)
	edns := b.Build()
	cc, sc, ok := findCookie(edns)
	require.True(t, ok)
	require.NotEqual(t, [8]byte{}, cc)
	require.Empty(t, sc)

	// Server replies with a cookie. Observe stores it.
	respEDNS := wire.NewEDNSBuilder().Option(mustClientServer(t, cc, []byte{0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x1, 0x2})).Build()
	resp, err := wire.NewBuilder().Response(true).EDNS(respEDNS).Build()
	require.NoError(t, err)
	c.Observe(server, resp)

	// Next Apply now includes the server cookie.
	b2 := wire.NewEDNSBuilder()
	b2 = c.Apply(server, b2)
	cc2, sc2, ok := findCookie(b2.Build())
	require.True(t, ok)
	require.Equal(t, cc, cc2)
	require.Equal(t, []byte{0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x1, 0x2}, sc2)

	// Server replies BADCOOKIE with a fresh server cookie. Retry updates
	// the cache and reports ok=true. BADCOOKIE=23 requires the high nibble
	// in the OPT pseudo-RR (RFC 6891 §6.1.3): low 4 bits in header (7),
	// high 8 bits in EDNS.ExtendedRCODE (1).
	freshSC := []byte{1, 1, 1, 1, 1, 1, 1, 1}
	respEDNS2 := wire.NewEDNSBuilder().
		ExtendedRCODE(1).
		Option(mustClientServer(t, cc, freshSC)).
		Build()
	resp2, _ := wire.NewBuilder().Response(true).RCODE(7).EDNS(respEDNS2).Build()
	ok, err = c.Retry(server, resp2)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestClientRetryNotBADCOOKIENoOp(t *testing.T) {
	t.Parallel()
	c := cookies.NewClient()
	server := netip.MustParseAddrPort("198.51.100.10:53")
	resp, _ := wire.NewBuilder().Response(true).Build()
	ok, err := c.Retry(server, resp)
	require.NoError(t, err)
	require.False(t, ok)
}

func findCookie(e wire.EDNS) ([8]byte, []byte, bool) {
	var zero [8]byte
	for _, o := range e.Options() {
		if o.Code() != wire.EDNSOptionCookie {
			continue
		}
		return wire.Cookies(o)
	}
	return zero, nil, false
}

func mustClientServer(t *testing.T, cc [8]byte, sc []byte) wire.EDNSOption {
	t.Helper()
	o, err := wire.NewClientServerCookie(cc, sc)
	require.NoError(t, err)
	return o
}
