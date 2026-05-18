package recursive_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/recursive"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// TestWithMaxPositiveTTLClampsCachedEntry pins WithMaxPositiveTTL's
// behaviour: even when an authoritative answer carries a long TTL, the
// recursive cache entry expires no later than the configured cap. The
// fixture zone publishes a 1-hour TTL; with a 1-second cap the cached
// entry's expiry must be within ~1 second of "now".
func TestWithMaxPositiveTTLClampsCachedEntry(t *testing.T) {
	t.Parallel()
	authAddr := startAuth(t, `$ORIGIN example.com.
$TTL 3600
@   IN  SOA  ns1.example.com. hm.example.com. ( 1 2 3 4 5 )
@   IN  NS   ns1.example.com.
ns1 IN  A    192.0.2.10
www IN  A    192.0.2.42
`)
	cache := recursive.NewMemoryCache()
	r := mustRecursive(t,
		recursive.WithRoots(authAddr),
		recursive.WithCache(cache),
		recursive.WithMaxPositiveTTL(1*time.Second),
	)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	_, err := r.ResolveEntry(ctx, wire.MustParseName("www.example.com"), rrtype.A)
	require.NoError(t, err)

	got, ok := cache.Get(wire.MustParseName("www.example.com"), rrtype.ClassIN, rrtype.A)
	require.True(t, ok, "the resolved answer must be cached")
	remaining := time.Until(got.ExpiresAt())
	require.LessOrEqual(t, remaining, 1*time.Second+200*time.Millisecond,
		"the cached entry's remaining TTL must respect WithMaxPositiveTTL (got %s)", remaining)
}

// TestWithMaxNegativeTTLClampsNXDOMAIN: same shape as the positive cap
// but for NXDOMAIN. The fixture zone's SOA minimum is 3600s; with a
// 1-second cap the NXDOMAIN cache entry must expire within ~1 second.
func TestWithMaxNegativeTTLClampsNXDOMAIN(t *testing.T) {
	t.Parallel()
	authAddr := startAuth(t, `$ORIGIN example.com.
$TTL 60
@   IN  SOA  ns1.example.com. hm.example.com. ( 1 60 60 60 3600 )
@   IN  NS   ns1.example.com.
ns1 IN  A    192.0.2.10
`)
	cache := recursive.NewMemoryCache()
	r := mustRecursive(t,
		recursive.WithRoots(authAddr),
		recursive.WithCache(cache),
		recursive.WithMaxNegativeTTL(1*time.Second),
	)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	_, _ = r.ResolveEntry(ctx, wire.MustParseName("nx.example.com"), rrtype.A)

	got, ok := cache.Get(wire.MustParseName("nx.example.com"), rrtype.ClassIN, rrtype.A)
	require.True(t, ok, "the NXDOMAIN response must be cached")
	require.Equal(t, wire.RCODENXDomain, got.RCODE())
	remaining := time.Until(got.ExpiresAt())
	require.LessOrEqual(t, remaining, 1*time.Second+200*time.Millisecond,
		"the cached NXDOMAIN's remaining TTL must respect WithMaxNegativeTTL (got %s)", remaining)
}

// TestWithUpstreamRateLimitExhaustionSurfacesErr exercises the
// per-upstream token bucket: once the bucket for the only configured
// upstream is exhausted, subsequent queries return ErrUpstreamRateLimited
// rather than queuing or silently failing. The test points at an
// unreachable address so the first attempt drains the token via a
// quick dial-timeout path rather than depending on a working resolver.
func TestWithUpstreamRateLimitExhaustionSurfacesErr(t *testing.T) {
	t.Parallel()
	// Tiny burst that QNAME-minimisation-disabled resolution can
	// drain in one go; near-zero qps means refill won't happen during
	// the test's wall-clock window.
	r := mustRecursive(t,
		recursive.WithRoots(netip.MustParseAddrPort("127.0.0.1:1")),
		recursive.WithUpstreamRateLimit(0.001, 1),
		recursive.WithQueryTimeout(50*time.Millisecond),
		recursive.WithResolveBudget(200*time.Millisecond),
	)

	// First resolve: token is taken, dial then times out — outcome is
	// an error but the bucket is now empty for that AddrPort.
	ctx1, cancel1 := context.WithTimeout(t.Context(), 500*time.Millisecond)
	_, _ = r.ResolveEntry(ctx1, wire.MustParseName("first.example."), rrtype.A)
	cancel1()

	// Second resolve: bucket empty for the only candidate ⇒ Take
	// returns false ⇒ ErrUpstreamRateLimited bubbles out.
	ctx2, cancel2 := context.WithTimeout(t.Context(), 500*time.Millisecond)
	_, err := r.ResolveEntry(ctx2, wire.MustParseName("second.example."), rrtype.A)
	cancel2()
	require.Error(t, err, "second resolve must fail when the only upstream is rate-limited")
	require.True(t, errors.Is(err, recursive.ErrUpstreamRateLimited),
		"second resolve must surface ErrUpstreamRateLimited (got %v)", err)
}

// stallingDialer is a recursive.Dialer that blocks forever on Exchange,
// letting the test pin a slow in-flight upstream call so the inflight
// semaphore stays occupied. The first call enters and blocks; the
// stallEntered channel signals readiness so subsequent callers race the
// cap rather than the dialer.
type stallingDialer struct {
	stallEntered chan struct{}
}

func (s *stallingDialer) Exchange(ctx context.Context, _ netip.AddrPort, _ wire.Message) (wire.Message, error) {
	select {
	case s.stallEntered <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return wire.Message{}, ctx.Err()
}

// TestWithMaxInflightSaturatesReturnsErrInflightFull pins the
// fail-fast contract on the recursive resolver: with maxInflight=1 and
// a single in-flight slow upstream, additional distinct queries see
// ErrInflightFull rather than queuing behind the semaphore.
func TestWithMaxInflightSaturatesReturnsErrInflightFull(t *testing.T) {
	t.Parallel()
	stall := &stallingDialer{stallEntered: make(chan struct{}, 1)}
	r := mustRecursive(t,
		recursive.WithRoots(netip.MustParseAddrPort("127.0.0.1:1")),
		recursive.WithDialer(stall),
		recursive.WithMaxInflight(1),
	)

	// First query enters the inflight slot and blocks on the stalled dialer.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _ = r.ResolveEntry(ctx, wire.MustParseName("first.example."), rrtype.A)
	}()
	select {
	case <-stall.stallEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("first query never reached the dialer")
	}

	// Second query: distinct singleflight key, hits the cap, fails fast.
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	_, err := r.ResolveEntry(ctx, wire.MustParseName("second.example."), rrtype.A)
	require.Error(t, err)
	require.True(t, errors.Is(err, recursive.ErrInflightFull) || errors.Is(err, acidns.ErrInflightFull),
		"second query must surface ErrInflightFull (got %v)", err)
}

// TestWithMemoryCacheMaxRecordsPerEntryTrimsOversized pins the
// MemoryCache's per-entry record cap: an oversized Entry is trimmed
// (additional first, then authority, then answer) so the stored Entry
// respects the limit, instead of consuming unbounded memory.
func TestWithMemoryCacheMaxRecordsPerEntryTrimsOversized(t *testing.T) {
	t.Parallel()
	c := recursive.NewMemoryCache(recursive.WithMemoryCacheMaxRecordsPerEntry(2))
	name := wire.MustParseName("x.example.")
	ar1, _ := rdata.NewA(netip.MustParseAddr("192.0.2.1"))
	ar2, _ := rdata.NewA(netip.MustParseAddr("192.0.2.2"))
	ar3, _ := rdata.NewA(netip.MustParseAddr("192.0.2.3"))
	ar4, _ := rdata.NewA(netip.MustParseAddr("192.0.2.4"))
	mkRec := func(rd rdata.RData) wire.Record { return wire.NewRecord(name, time.Hour, rd) }

	// 4 total records (1 answer + 1 authority + 2 additional) → trim
	// 2 from additional first, then nothing else. Final stored entry
	// has 1 answer + 1 authority + 0 additional = 2 records.
	bigEntry := mustEntry(t, recursive.NewEntryBuilder().
		Answer([]wire.Record{mkRec(ar1)}).
		Authority([]wire.Record{mkRec(ar2)}).
		Additional([]wire.Record{mkRec(ar3), mkRec(ar4)}).
		RCODE(wire.RCODENoError).
		TTL(time.Hour),
	)
	c.Put(name, rrtype.ClassIN, rrtype.A, bigEntry)
	got, ok := c.Get(name, rrtype.ClassIN, rrtype.A)
	require.True(t, ok)
	total := len(got.Answer()) + len(got.Authority()) + len(got.Additional())
	require.LessOrEqual(t, total, 2, "Put must trim records past the cap")
	require.Len(t, got.Answer(), 1, "answer section must survive the trim")
	require.Empty(t, got.Additional(), "additional section is the first to be trimmed")
}

// TestNewScoreRoundTrip exercises the Score constructor — the only public
// way for a user-supplied ServerStats implementation to return a Score
// value, since the fields are unexported.
func TestNewScoreRoundTrip(t *testing.T) {
	t.Parallel()
	s := recursive.NewScore(42*time.Millisecond, 3)
	require.Equal(t, 42*time.Millisecond, s.RTT())
	require.Equal(t, 3, s.FailureStreak())
}

// TestRecursiveOptionsAcceptedConstructionOnly covers the options that
// gate behaviour requiring infrastructure too heavy to set up inside a
// per-option coverage test:
//
//   - WithMaxDepth: requires a CNAME chain or out-of-bailiwick NS graph
//     deep enough to bump the cap.
//   - WithCaseRandomization: requires intercepting outbound wire bytes
//     and asserting 0x20 case toggles (covered indirectly by the
//     exchanger-level tests in exchanger_udp_caserand_test.go).
//   - WithUpstreamRateLimitMaxKeys: drives an internal eviction policy
//     that's exercised in the upstream_ratelimit_test.go bench/coverage.
//
// We construct with each option so removing one is a compile-time
// failure even if no behavioural test covers it directly.
func TestRecursiveOptionsAcceptedConstructionOnly(t *testing.T) {
	t.Parallel()
	r, err := recursive.New(
		recursive.WithRoots(netip.MustParseAddrPort("127.0.0.1:1")),
		recursive.WithMaxDepth(6),
		recursive.WithCaseRandomization(false),
		recursive.WithUpstreamRateLimitMaxKeys(8192),
	)
	require.NoError(t, err)
	require.NotNil(t, r)
}
