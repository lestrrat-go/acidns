package cookies_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/cookies"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/stretchr/testify/require"
)

// TestSecretPoolAutoRotation exercises the background-rotation goroutine
// path of NewSecretPool. We pick a short interval and check that Current()
// changes within a generous window.
func TestSecretPoolAutoRotation(t *testing.T) {
	t.Parallel()
	pool, _ := cookies.NewSecretPool(cookies.WithPoolRotateEvery(5 * time.Millisecond))
	t.Cleanup(pool.Close)

	first := append([]byte(nil), pool.Current()...)
	require.NotEmpty(t, first)

	require.Eventually(t, func() bool {
		return string(pool.Current()) != string(first)
	}, 2*time.Second, 5*time.Millisecond, "secret pool did not rotate within deadline")
	require.GreaterOrEqual(t, len(pool.All()), 2)
}

// TestSecretPoolCancelStopsRotation verifies that the cancel function
// stops the background rotation loop without panicking.
func TestSecretPoolCancelStopsRotation(t *testing.T) {
	t.Parallel()
	pool, _ := cookies.NewSecretPool(cookies.WithPoolRotateEvery(time.Hour))
	pool.Close() // immediately stop; should not block / panic.
}

// TestServerMaxAgeDefault checks that NewServer with maxAge=0 defaults to
// one hour, and that explicit non-zero values are preserved.
func TestServerMaxAgeDefault(t *testing.T) {
	t.Parallel()
	pool, _ := cookies.NewSecretPool()
	t.Cleanup(pool.Close)

	srv, err := cookies.NewServer(pool)
	require.NoError(t, err)
	require.Equal(t, time.Hour, srv.MaxAge())

	srv2, err := cookies.NewServer(pool, cookies.WithMaxAge(17*time.Minute))
	require.NoError(t, err)
	require.Equal(t, 17*time.Minute, srv2.MaxAge())
}

// TestServerValidateMalformedCookies covers length and version validation.
func TestServerValidateMalformedCookies(t *testing.T) {
	t.Parallel()
	pool, _ := cookies.NewSecretPool()
	t.Cleanup(pool.Close)
	srv, err := cookies.NewServer(pool)
	require.NoError(t, err)
	cc := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	addr := netip.MustParseAddr("203.0.113.99")
	now := time.Unix(1_700_000_000, 0).UTC()

	// Wrong length.
	_, err = srv.Validate(make([]byte, 8), cc, addr, now)
	require.ErrorIs(t, err, cookies.ErrCookieMalformed)

	// Wrong version (byte 0 != 1).
	bad := make([]byte, 16)
	bad[0] = 9
	_, err = srv.Validate(bad, cc, addr, now)
	require.ErrorIs(t, err, cookies.ErrCookieMalformed)
}

// TestServerValidateFutureTimestamp ensures the >5-minute future-timestamp
// guard rejects clearly bogus cookies.
func TestServerValidateFutureTimestamp(t *testing.T) {
	t.Parallel()
	pool, _ := cookies.NewSecretPool()
	t.Cleanup(pool.Close)
	srv, err := cookies.NewServer(pool)
	require.NoError(t, err)
	cc := [8]byte{}
	addr := netip.MustParseAddr("203.0.113.50")
	future := time.Unix(1_700_000_000, 0).UTC()
	cookie := srv.Make(cc, addr, future)

	// "now" is 10 minutes BEFORE the cookie's timestamp.
	_, err = srv.Validate(cookie, cc, addr, future.Add(-10*time.Minute))
	require.ErrorIs(t, err, cookies.ErrCookieExpired)
}

// TestServerCookieIPv6 exercises the addr.Is6() branch of mintCookie.
func TestServerCookieIPv6(t *testing.T) {
	t.Parallel()
	pool, _ := cookies.NewSecretPool()
	t.Cleanup(pool.Close)
	srv, err := cookies.NewServer(pool)
	require.NoError(t, err)
	cc := [8]byte{9, 9, 9, 9, 9, 9, 9, 9}
	addr := netip.MustParseAddr("2001:db8::1")
	now := time.Unix(1_700_000_000, 0).UTC()

	cookie := srv.Make(cc, addr, now)
	_, err = srv.Validate(cookie, cc, addr, now)
	require.NoError(t, err)

	// Different IPv6 address → mismatch.
	other := netip.MustParseAddr("2001:db8::2")
	_, err = srv.Validate(cookie, cc, other, now)
	require.ErrorIs(t, err, cookies.ErrCookieMismatch)
}

// TestServerCookieZeroAddr exercises the default branch of mintCookie when
// addr is the zero value (neither Is4 nor Is6).
func TestServerCookieZeroAddr(t *testing.T) {
	t.Parallel()
	pool, _ := cookies.NewSecretPool()
	t.Cleanup(pool.Close)
	srv, err := cookies.NewServer(pool)
	require.NoError(t, err)
	cc := [8]byte{}
	var zero netip.Addr
	now := time.Unix(1_700_000_000, 0).UTC()

	cookie := srv.Make(cc, zero, now)
	_, err = srv.Validate(cookie, cc, zero, now)
	require.NoError(t, err)
}

// TestClientApplyIPv6Server exercises Apply with an IPv6 server addrport;
// also checks that repeated Apply on the same server reuses the client
// cookie cached on first call.
func TestClientApplyReusesClientCookie(t *testing.T) {
	t.Parallel()
	c, err := cookies.NewClient()
	require.NoError(t, err)
	server := netip.MustParseAddrPort("[2001:db8::53]:53")

	b := wire.NewEDNSBuilder()
	b = c.Apply(server, b)
	cc1, sc1, ok := findCookie(mustEDNS(t, b))
	require.True(t, ok)
	require.Empty(t, sc1)

	b2 := wire.NewEDNSBuilder()
	b2 = c.Apply(server, b2)
	cc2, _, ok := findCookie(mustEDNS(t, b2))
	require.True(t, ok)
	require.Equal(t, cc1, cc2)
}

// TestClientObserveIgnoresMissingCookie verifies Observe is a no-op when
// the response carries no cookie option, leaving the cache empty so a
// subsequent Apply still emits client-only.
func TestClientObserveIgnoresMissingCookie(t *testing.T) {
	t.Parallel()
	c, err := cookies.NewClient()
	require.NoError(t, err)
	server := netip.MustParseAddrPort("198.51.100.20:53")

	// Response with no EDNS at all.
	resp, err := wire.NewMessageBuilder().Response(true).Build()
	require.NoError(t, err)
	c.Observe(server, resp) // must not panic / set state.

	// Apply: no server cookie should be emitted.
	b := wire.NewEDNSBuilder()
	b = c.Apply(server, b)
	_, sc, ok := findCookie(mustEDNS(t, b))
	require.True(t, ok)
	require.Empty(t, sc)
}

// TestClientObserveIgnoresShortCookie covers the len(sc)<8 branch of
// Observe.
func TestClientObserveIgnoresShortCookie(t *testing.T) {
	t.Parallel()
	c, err := cookies.NewClient()
	require.NoError(t, err)
	server := netip.MustParseAddrPort("198.51.100.21:53")

	// Server cookie shorter than 8 bytes is not allowed by
	// NewClientServerCookie, so build an option from a client-only cookie
	// (zero server bytes).
	cc := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	respEDNS := mustEDNS(t, wire.NewEDNSBuilder().Option(wire.NewClientCookie(cc)))
	resp, err := wire.NewMessageBuilder().Response(true).EDNS(respEDNS).Build()
	require.NoError(t, err)
	c.Observe(server, resp)

	// State should still treat us as fresh: server cookie empty.
	b := wire.NewEDNSBuilder()
	b = c.Apply(server, b)
	_, sc, ok := findCookie(mustEDNS(t, b))
	require.True(t, ok)
	require.Empty(t, sc)
}

// TestClientRetryMissingCookie covers the BADCOOKIE-without-cookie path.
func TestClientRetryMissingCookie(t *testing.T) {
	t.Parallel()
	c, err := cookies.NewClient()
	require.NoError(t, err)
	server := netip.MustParseAddrPort("198.51.100.30:53")

	// Build a BADCOOKIE response with EDNS but no cookie option.
	respEDNS := mustEDNS(t, wire.NewEDNSBuilder().ExtendedRCODE(1))
	resp, err := wire.NewMessageBuilder().Response(true).RCODE(7).EDNS(respEDNS).Build()
	require.NoError(t, err)
	ok, err := c.Retry(server, resp)
	require.False(t, ok)
	require.ErrorIs(t, err, cookies.ErrCookieMissing)

	// And BADCOOKIE without any EDNS at all: also missing.
	resp2, err := wire.NewMessageBuilder().Response(true).RCODE(7).Build()
	require.NoError(t, err)
	// Without OPT the extended rcode is just the low 4 bits = 7, not 23,
	// so Retry returns ok=false, nil — exercises the early-return branch.
	ok, err = c.Retry(server, resp2)
	require.NoError(t, err)
	require.False(t, ok)
}

// TestClientRetryShortServerCookie covers the len(sc)<8 branch of Retry.
// We can't legitimately construct a BADCOOKIE with <8-byte server cookie
// via NewClientServerCookie (it rejects it), so use a client-only option
// and rely on extractCookieFromMsg returning sc=nil.
func TestClientRetryShortServerCookie(t *testing.T) {
	t.Parallel()
	c, err := cookies.NewClient()
	require.NoError(t, err)
	server := netip.MustParseAddrPort("198.51.100.31:53")
	cc := [8]byte{2, 2, 2, 2, 2, 2, 2, 2}

	respEDNS := mustEDNS(t, wire.NewEDNSBuilder().
		ExtendedRCODE(1).
		Option(wire.NewClientCookie(cc)))
	resp, err := wire.NewMessageBuilder().Response(true).RCODE(7).EDNS(respEDNS).Build()
	require.NoError(t, err)
	ok, err := c.Retry(server, resp)
	require.False(t, ok)
	require.ErrorIs(t, err, cookies.ErrCookieTooShort)
}

// TestClientObserveSkipsNonCookieOptions feeds a response carrying a
// non-cookie EDNS option to exercise the "Code != EDNSOptionCookie" loop
// branch in extractCookieFromMsg.
func TestClientObserveSkipsNonCookieOptions(t *testing.T) {
	t.Parallel()
	c, err := cookies.NewClient()
	require.NoError(t, err)
	server := netip.MustParseAddrPort("198.51.100.40:53")

	// Build EDNS with only an extended-error option (not a cookie).
	ede := wire.NewExtendedError(0, "")
	respEDNS := mustEDNS(t, wire.NewEDNSBuilder().Option(ede))
	resp, err := wire.NewMessageBuilder().Response(true).EDNS(respEDNS).Build()
	require.NoError(t, err)
	c.Observe(server, resp) // must not crash / set cache.

	b := wire.NewEDNSBuilder()
	b = c.Apply(server, b)
	_, sc, ok := findCookie(mustEDNS(t, b))
	require.True(t, ok)
	require.Empty(t, sc)
}

// TestClientCacheEvictsAtMaxEntries verifies that the LRU cap drops
// the oldest entry when a new server is encountered, and that the
// most-recently-touched entry survives. Without the cap a long-
// running recursive resolver would grow the map unboundedly.
func TestClientCacheEvictsAtMaxEntries(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	c, err := cookies.NewClient(
		cookies.WithClientMaxEntries(4),
		cookies.WithClientClock(func() time.Time { return now }),
	)
	require.NoError(t, err)

	// Fill the cap with four distinct servers, advancing the clock
	// each time so the LRU ordering is well-defined.
	addrs := []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.1:53"),
		netip.MustParseAddrPort("192.0.2.2:53"),
		netip.MustParseAddrPort("192.0.2.3:53"),
		netip.MustParseAddrPort("192.0.2.4:53"),
	}
	firstCookies := make(map[netip.AddrPort][8]byte)
	for _, a := range addrs {
		now = now.Add(time.Second)
		cc, _, _ := findCookie(mustEDNS(t, c.Apply(a, wire.NewEDNSBuilder())))
		firstCookies[a] = cc
	}

	// Touch the second server so it's the most-recently-used; the
	// oldest is now addrs[0].
	now = now.Add(time.Second)
	_, _, _ = findCookie(mustEDNS(t, c.Apply(addrs[1], wire.NewEDNSBuilder())))

	// Insert a fifth server: addrs[0] (the oldest by touch time) must
	// be evicted to make room.
	now = now.Add(time.Second)
	fifth := netip.MustParseAddrPort("192.0.2.5:53")
	_, _, _ = findCookie(mustEDNS(t, c.Apply(fifth, wire.NewEDNSBuilder())))

	// addrs[1] was the most-recently-touched survivor — its client
	// cookie must be the same one that was minted on its first Apply.
	cc1, _, ok := findCookie(mustEDNS(t, c.Apply(addrs[1], wire.NewEDNSBuilder())))
	require.True(t, ok)
	require.Equal(t, firstCookies[addrs[1]], cc1)

	// addrs[0] should have been evicted: re-applying mints a fresh
	// client cookie, so it must differ from the original. (Random
	// 8-byte clash is a 1-in-2^64 false negative — fine.)
	now = now.Add(time.Second)
	cc0, _, ok := findCookie(mustEDNS(t, c.Apply(addrs[0], wire.NewEDNSBuilder())))
	require.True(t, ok)
	require.NotEqual(t, firstCookies[addrs[0]], cc0)
}
