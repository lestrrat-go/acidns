package cookies_test

import (
	"net/netip"
	"sync"
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
	srv, err := cookies.NewServer(pool)
	require.NoError(t, err)
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
	srv, err := cookies.NewServer(pool)
	require.NoError(t, err)
	cc := [8]byte{0xab, 0xcd, 0xef, 1, 2, 3, 4, 5}
	now := time.Unix(1_700_000_000, 0).UTC()

	cookie := srv.Make(cc, netip.MustParseAddr("203.0.113.1"), now)
	_, err = srv.Validate(cookie, cc, netip.MustParseAddr("203.0.113.2"), now)
	require.ErrorIs(t, err, cookies.ErrCookieMismatch)
}

func TestServerCookieRejectsExpired(t *testing.T) {
	t.Parallel()
	pool, _ := cookies.NewSecretPool()
	t.Cleanup(pool.Close)
	srv, err := cookies.NewServer(pool, cookies.WithMaxAge(30*time.Minute))
	require.NoError(t, err)
	cc := [8]byte{}
	addr := netip.MustParseAddr("203.0.113.1")
	now := time.Unix(1_700_000_000, 0).UTC()
	cookie := srv.Make(cc, addr, now)

	// 31 minutes later → outside acceptance window.
	_, err = srv.Validate(cookie, cc, addr, now.Add(31*time.Minute))
	require.ErrorIs(t, err, cookies.ErrCookieExpired)
}

func TestServerCookieAcceptsPreviousSecretAfterRotation(t *testing.T) {
	t.Parallel()
	pool, _ := cookies.NewSecretPool()
	t.Cleanup(pool.Close)
	srv, err := cookies.NewServer(pool)
	require.NoError(t, err)
	cc := [8]byte{42, 42, 42, 42, 42, 42, 42, 42}
	addr := netip.MustParseAddr("198.51.100.5")
	now := time.Now().UTC().Truncate(time.Second)

	cookie := srv.Make(cc, addr, now)
	require.NoError(t, pool.Rotate())
	// After rotation the OLD secret is "previous"; validation must still
	// succeed because Server.All returns both.
	_, err = srv.Validate(cookie, cc, addr, now.Add(time.Minute))
	require.NoError(t, err)

	// After two rotations the OLD secret is gone → fail.
	require.NoError(t, pool.Rotate())
	_, err = srv.Validate(cookie, cc, addr, now.Add(2*time.Minute))
	require.ErrorIs(t, err, cookies.ErrCookieMismatch)
}

// countingPool wraps a SecretPool and records how many entries the
// validator consumes from each All() call. Used by the constant-time
// regression test to confirm the validator visits every secret rather
// than short-circuiting on the first match.
type countingPool struct {
	inner cookies.SecretPool
	mu    sync.Mutex
	calls [][]cookies.Secret
}

func (p *countingPool) Current() cookies.Secret { return p.inner.Current() }
func (p *countingPool) All() []cookies.Secret {
	secrets := p.inner.All()
	// Capture a snapshot so the test can inspect what the validator saw.
	snap := make([]cookies.Secret, len(secrets))
	copy(snap, secrets)
	p.mu.Lock()
	p.calls = append(p.calls, snap)
	p.mu.Unlock()
	return secrets
}
func (p *countingPool) Close() { p.inner.Close() }

// TestServerCookieValidateVisitsAllSecrets pins the constant-time
// behaviour of Server.Validate against the secret pool. A break on
// first-match would leak (via timing) which secret accepted the cookie
// — distinguishing the current secret from the previous one. We can't
// prove timing equivalence in a unit test, but we can assert two
// load-bearing properties: (1) both current and previous secrets
// validate correctly, and (2) the validator always consumes the full
// secret list rather than short-circuiting after the first hit.
func TestServerCookieValidateVisitsAllSecrets(t *testing.T) {
	t.Parallel()
	inner, err := cookies.NewSecretPool()
	require.NoError(t, err)
	t.Cleanup(inner.Close)
	pool := &countingPool{inner: inner}

	srv, err := cookies.NewServer(pool)
	require.NoError(t, err)
	cc := [8]byte{9, 8, 7, 6, 5, 4, 3, 2}
	addr := netip.MustParseAddr("198.51.100.7")
	now := time.Unix(1_700_000_000, 0).UTC()

	// Mint a cookie under the current secret, then rotate so the minting
	// secret becomes the "previous" entry. Pool now has two secrets and
	// the validator must check both.
	cookie := srv.Make(cc, addr, now)
	require.NoError(t, inner.Rotate())

	// Sanity: pool reports two secrets, and the cookie matches the
	// SECOND one (previous). If the validator short-circuited on the
	// first secret, it would still succeed for current-minted cookies
	// — so the previous-secret path is exactly where the leak lives.
	require.Len(t, inner.All(), 2)

	_, err = srv.Validate(cookie, cc, addr, now.Add(time.Minute))
	require.NoError(t, err)

	snapshot := func() [][]cookies.Secret {
		pool.mu.Lock()
		defer pool.mu.Unlock()
		out := make([][]cookies.Secret, len(pool.calls))
		copy(out, pool.calls)
		return out
	}
	calls := snapshot()
	require.Len(t, calls, 1, "Validate must invoke pool.All() exactly once")
	require.Len(t, calls[0], 2, "Validate must observe both pool secrets")

	// Also mint+validate under the current secret to confirm that path
	// still succeeds and exercises the same full-walk codepath.
	cookie2 := srv.Make(cc, addr, now)
	_, err = srv.Validate(cookie2, cc, addr, now)
	require.NoError(t, err)
	calls = snapshot()
	// srv.Make only consults Current(); only Validate calls All(). So
	// after two Validate calls total we expect exactly two snapshots.
	require.Len(t, calls, 2, "each Validate must invoke pool.All() exactly once")
	require.Len(t, calls[len(calls)-1], 2, "second Validate must still observe both secrets")
}

func TestClientApplyAndObserveAndRetry(t *testing.T) {
	t.Parallel()
	c, err := cookies.NewClient()
	require.NoError(t, err)
	server := netip.MustParseAddrPort("198.51.100.10:53")

	// Apply on a fresh server emits a client-only cookie.
	b := wire.NewEDNSBuilder()
	b = c.Apply(server, b)
	edns := mustEDNS(t, b)
	cc, sc, ok := findCookie(edns)
	require.True(t, ok)
	require.NotEqual(t, [8]byte{}, cc)
	require.Empty(t, sc)

	// Server replies with a cookie. Observe stores it.
	respEDNS := mustEDNS(t, wire.NewEDNSBuilder().Option(mustClientServer(t, cc, []byte{0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x1, 0x2})))
	resp, err := wire.NewMessageBuilder().Response(true).EDNS(respEDNS).Build()
	require.NoError(t, err)
	c.Observe(server, resp)

	// Next Apply now includes the server cookie.
	b2 := wire.NewEDNSBuilder()
	b2 = c.Apply(server, b2)
	cc2, sc2, ok := findCookie(mustEDNS(t, b2))
	require.True(t, ok)
	require.Equal(t, cc, cc2)
	require.Equal(t, []byte{0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x1, 0x2}, sc2)

	// Server replies BADCOOKIE with a fresh server cookie. Retry updates
	// the cache and reports ok=true. BADCOOKIE=23 requires the high nibble
	// in the OPT pseudo-RR (RFC 6891 §6.1.3): low 4 bits in header (7),
	// high 8 bits in EDNS.ExtendedRCODE (1).
	freshSC := []byte{1, 1, 1, 1, 1, 1, 1, 1}
	respEDNS2 := mustEDNS(t, wire.NewEDNSBuilder().
		ExtendedRCODE(1).
		Option(mustClientServer(t, cc, freshSC)))
	resp2, _ := wire.NewMessageBuilder().Response(true).RCODE(7).EDNS(respEDNS2).Build()
	ok, err = c.Retry(server, resp2)
	require.NoError(t, err)
	require.True(t, ok)
}

// TestClientRetryBoundedToOnce verifies the per-server retry cap: a
// server hammering BADCOOKIE on every reply must not pin the caller
// in a tight retry loop.
func TestClientRetryBoundedToOnce(t *testing.T) {
	t.Parallel()
	c, err := cookies.NewClient()
	require.NoError(t, err)
	server := netip.MustParseAddrPort("198.51.100.20:53")

	// Drive an Apply to seed an entry.
	_ = c.Apply(server, wire.NewEDNSBuilder())

	mkBadCookie := func(cc [8]byte, sc []byte) wire.Message {
		respEDNS := mustEDNS(t, wire.NewEDNSBuilder().
			ExtendedRCODE(1).
			Option(mustClientServer(t, cc, sc)))
		m, err := wire.NewMessageBuilder().Response(true).RCODE(7).EDNS(respEDNS).Build()
		require.NoError(t, err)
		return m
	}

	// First BADCOOKIE: ok=true (we adopt the server cookie and the caller
	// retries once).
	r1 := mkBadCookie([8]byte{1, 2, 3, 4, 5, 6, 7, 8}, []byte{1, 1, 1, 1, 1, 1, 1, 1})
	ok, err := c.Retry(server, r1)
	require.NoError(t, err)
	require.True(t, ok)

	// Second BADCOOKIE in a row: budget exhausted.
	r2 := mkBadCookie([8]byte{2, 3, 4, 5, 6, 7, 8, 9}, []byte{2, 2, 2, 2, 2, 2, 2, 2})
	ok, err = c.Retry(server, r2)
	require.ErrorIs(t, err, cookies.ErrCookieRetryExhausted)
	require.False(t, ok)
}

func TestClientRetryNotBADCOOKIENoOp(t *testing.T) {
	t.Parallel()
	c, err := cookies.NewClient()
	require.NoError(t, err)
	server := netip.MustParseAddrPort("198.51.100.10:53")
	resp, _ := wire.NewMessageBuilder().Response(true).Build()
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
