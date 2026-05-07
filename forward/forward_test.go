package forward_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/forward"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// fakeClock returns a controllable time. Tests advance it via Advance to
// verify TTL-driven expiry without sleeping in real time.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 5, 7, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// fakeUpstream is an Exchanger whose answer is decided by handler — the
// test inspects upstream-side queries via a counter and an optional spy.
type fakeUpstream struct {
	calls   atomic.Int64
	handler func(q wire.Message) wire.Message
}

func (f *fakeUpstream) Exchange(_ context.Context, q wire.Message) (wire.Message, error) {
	f.calls.Add(1)
	return f.handler(q), nil
}

func answer(q wire.Message, ttl time.Duration, addr netip.Addr) wire.Message {
	a, _ := wire.NewBuilder().
		ID(q.ID()).
		Response(true).
		RecursionDesired(q.Flags().RecursionDesired()).
		RecursionAvailable(true).
		Question(q.Questions()[0]).
		Answer(wire.NewRecord(q.Questions()[0].Name(), ttl, rdata.NewA(addr))).
		Build()
	return a
}

func nxdomain(q wire.Message, soaTTL, soaMin time.Duration) wire.Message {
	soa := rdata.NewSOA(
		wire.MustParseName("ns.example."),
		wire.MustParseName("hostmaster.example."),
		1, time.Hour, time.Minute, 24*time.Hour, soaMin,
	)
	a, _ := wire.NewBuilder().
		ID(q.ID()).
		Response(true).
		RecursionDesired(q.Flags().RecursionDesired()).
		RecursionAvailable(true).
		RCODE(wire.RCODENXDomain).
		Question(q.Questions()[0]).
		Authority(wire.NewRecord(wire.MustParseName("example."), soaTTL, soa)).
		Build()
	return a
}

func nodata(q wire.Message, soaTTL, soaMin time.Duration) wire.Message {
	soa := rdata.NewSOA(
		wire.MustParseName("ns.example."),
		wire.MustParseName("hostmaster.example."),
		1, time.Hour, time.Minute, 24*time.Hour, soaMin,
	)
	a, _ := wire.NewBuilder().
		ID(q.ID()).
		Response(true).
		RecursionDesired(q.Flags().RecursionDesired()).
		RecursionAvailable(true).
		Question(q.Questions()[0]).
		Authority(wire.NewRecord(wire.MustParseName("example."), soaTTL, soa)).
		Build()
	return a
}

func clientQuery(t *testing.T, name string, qtype rrtype.Type) wire.Message {
	t.Helper()
	q, err := wire.NewBuilder().
		ID(0xabcd).
		RecursionDesired(true).
		Question(wire.NewQuestion(wire.MustParseName(name), qtype)).
		Build()
	require.NoError(t, err)
	return q
}

// captureWriter is a ResponseWriter that just stashes the message.
type captureWriter struct {
	got wire.Message
}

func (c *captureWriter) WriteMsg(m wire.Message) error  { c.got = m; return nil }
func (c *captureWriter) RemoteAddr() netip.AddrPort     { return netip.AddrPort{} }
func (c *captureWriter) LocalAddr() netip.AddrPort      { return netip.AddrPort{} }
func (c *captureWriter) Network() string                { return "udp" }

func TestPositiveCacheHit(t *testing.T) {
	t.Parallel()
	upstream := &fakeUpstream{
		handler: func(q wire.Message) wire.Message {
			return answer(q, 5*time.Second, netip.MustParseAddr("203.0.113.10"))
		},
	}
	h, err := forward.New(forward.WithUpstream(upstream))
	require.NoError(t, err)

	q := clientQuery(t, "example.com", rrtype.A)
	for i := 0; i < 5; i++ {
		w := &captureWriter{}
		h.ServeDNS(t.Context(), w, q)
		require.NotNil(t, w.got)
		require.Equal(t, wire.RCODENoError, w.got.Flags().RCODE())
		require.Len(t, w.got.Answers(), 1)
	}
	require.Equal(t, int64(1), upstream.calls.Load(), "subsequent queries must be cache hits")
	require.Equal(t, 1, h.CacheSize())
}

func TestPositiveCacheTTLDecrements(t *testing.T) {
	t.Parallel()
	upstream := &fakeUpstream{
		handler: func(q wire.Message) wire.Message {
			return answer(q, 10*time.Second, netip.MustParseAddr("203.0.113.10"))
		},
	}
	clk := newFakeClock()
	h, err := forward.New(forward.WithUpstream(upstream), forward.WithNowFunc(clk.Now))
	require.NoError(t, err)

	q := clientQuery(t, "example.com", rrtype.A)
	w1 := &captureWriter{}
	h.ServeDNS(t.Context(), w1, q)
	first := w1.got.Answers()[0].TTL()

	clk.Advance(2 * time.Second)
	w2 := &captureWriter{}
	h.ServeDNS(t.Context(), w2, q)
	second := w2.got.Answers()[0].TTL()

	require.Less(t, second, first, "TTL on the cached response should decrement")
}

func TestPositiveCacheExpires(t *testing.T) {
	t.Parallel()
	upstream := &fakeUpstream{
		handler: func(q wire.Message) wire.Message {
			return answer(q, time.Second, netip.MustParseAddr("203.0.113.10"))
		},
	}
	clk := newFakeClock()
	h, err := forward.New(forward.WithUpstream(upstream), forward.WithNowFunc(clk.Now))
	require.NoError(t, err)

	q := clientQuery(t, "example.com", rrtype.A)
	w := &captureWriter{}
	h.ServeDNS(t.Context(), w, q)
	require.Equal(t, int64(1), upstream.calls.Load())

	clk.Advance(2 * time.Second)
	w = &captureWriter{}
	h.ServeDNS(t.Context(), w, q)
	require.Equal(t, int64(2), upstream.calls.Load(), "expired entry should refetch")
}

func TestNXDomainCachedFromSOAMinimum(t *testing.T) {
	t.Parallel()
	upstream := &fakeUpstream{
		handler: func(q wire.Message) wire.Message {
			return nxdomain(q, time.Hour, 30*time.Second)
		},
	}
	h, err := forward.New(forward.WithUpstream(upstream))
	require.NoError(t, err)

	q := clientQuery(t, "nope.example", rrtype.A)
	for i := 0; i < 3; i++ {
		w := &captureWriter{}
		h.ServeDNS(t.Context(), w, q)
		require.Equal(t, wire.RCODENXDomain, w.got.Flags().RCODE())
	}
	require.Equal(t, int64(1), upstream.calls.Load(), "NXDOMAIN must be cached")
}

func TestNoDataCached(t *testing.T) {
	t.Parallel()
	upstream := &fakeUpstream{
		handler: func(q wire.Message) wire.Message {
			return nodata(q, time.Hour, 30*time.Second)
		},
	}
	h, err := forward.New(forward.WithUpstream(upstream))
	require.NoError(t, err)

	q := clientQuery(t, "ipv6less.example", rrtype.AAAA)
	for i := 0; i < 3; i++ {
		w := &captureWriter{}
		h.ServeDNS(t.Context(), w, q)
		require.Equal(t, wire.RCODENoError, w.got.Flags().RCODE())
		require.Empty(t, w.got.Answers())
	}
	require.Equal(t, int64(1), upstream.calls.Load(), "NoData must be cached")
}

func TestNegativeCacheCappedByMaxNegTTL(t *testing.T) {
	t.Parallel()
	upstream := &fakeUpstream{
		handler: func(q wire.Message) wire.Message {
			// SOA MINIMUM is huge; cap should pull it down.
			return nxdomain(q, time.Hour, 24*time.Hour)
		},
	}
	clk := newFakeClock()
	h, err := forward.New(
		forward.WithUpstream(upstream),
		forward.WithMaxNegativeTTL(time.Second),
		forward.WithNowFunc(clk.Now),
	)
	require.NoError(t, err)

	q := clientQuery(t, "nope.example", rrtype.A)
	w := &captureWriter{}
	h.ServeDNS(t.Context(), w, q)
	require.Equal(t, int64(1), upstream.calls.Load())

	clk.Advance(2 * time.Second)
	w = &captureWriter{}
	h.ServeDNS(t.Context(), w, q)
	require.Equal(t, int64(2), upstream.calls.Load(), "negative cache should expire after maxNegTTL")
}

func TestServFailNotCached(t *testing.T) {
	t.Parallel()
	upstream := &fakeUpstream{
		handler: func(q wire.Message) wire.Message {
			a, _ := wire.NewBuilder().
				ID(q.ID()).
				Response(true).
				RCODE(wire.RCODEServFail).
				Question(q.Questions()[0]).
				Build()
			return a
		},
	}
	h, err := forward.New(forward.WithUpstream(upstream))
	require.NoError(t, err)

	q := clientQuery(t, "fail.example", rrtype.A)
	for i := 0; i < 3; i++ {
		w := &captureWriter{}
		h.ServeDNS(t.Context(), w, q)
	}
	require.Equal(t, int64(3), upstream.calls.Load(), "SERVFAIL must not be cached")
}

func TestUDPTCPFallbackEndToEnd(t *testing.T) {
	t.Parallel()
	// Stand up an upstream as a real authoritative-style handler over
	// UDP+TCP; the forwarder talks to it via the toolkit's standard
	// UDP-with-TCP-fallback path.
	upstreamHandler := acidns.HandlerFunc(func(_ context.Context, w acidns.ResponseWriter, q wire.Message) {
		_ = w.WriteMsg(answer(q, 30*time.Second, netip.MustParseAddr("198.51.100.7")))
	})
	udpSrv, err := acidns.ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"), upstreamHandler)
	require.NoError(t, err)
	tcpSrv, err := acidns.ListenTCP(udpSrv.Addr(), upstreamHandler)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = udpSrv.Serve(ctx) }()
	go func() { _ = tcpSrv.Serve(ctx) }()

	h, err := forward.New(forward.WithUDPUpstream(udpSrv.Addr()))
	require.NoError(t, err)

	w := &captureWriter{}
	h.ServeDNS(t.Context(), w, clientQuery(t, "example.com", rrtype.A))
	require.NotNil(t, w.got)
	require.Equal(t, wire.RCODENoError, w.got.Flags().RCODE())
	require.Len(t, w.got.Answers(), 1)
	require.Contains(t, h.UpstreamName(), udpSrv.Addr().String())
}

func TestNoUpstreamRejected(t *testing.T) {
	t.Parallel()
	_, err := forward.New()
	require.ErrorIs(t, err, forward.ErrNoUpstream)
}

func TestCacheCapacityZeroDisables(t *testing.T) {
	t.Parallel()
	upstream := &fakeUpstream{
		handler: func(q wire.Message) wire.Message {
			return answer(q, time.Hour, netip.MustParseAddr("203.0.113.10"))
		},
	}
	h, err := forward.New(
		forward.WithUpstream(upstream),
		forward.WithCacheSize(0),
	)
	require.NoError(t, err)

	q := clientQuery(t, "example.com", rrtype.A)
	for i := 0; i < 3; i++ {
		w := &captureWriter{}
		h.ServeDNS(t.Context(), w, q)
	}
	require.Equal(t, int64(3), upstream.calls.Load(), "size=0 must disable caching")
	require.Equal(t, 0, h.CacheSize())
}

// errUpstream surfaces a fixed error on every Exchange — used to exercise
// the SERVFAIL error path in ServeDNS when the upstream itself fails.
type errUpstream struct {
	calls atomic.Int64
	err   error
}

func (e *errUpstream) Exchange(_ context.Context, _ wire.Message) (wire.Message, error) {
	e.calls.Add(1)
	return nil, e.err
}

func TestUpstreamErrorReturnsServFail(t *testing.T) {
	t.Parallel()
	up := &errUpstream{err: errors.New("simulated upstream failure")}
	h, err := forward.New(forward.WithUpstream(up))
	require.NoError(t, err)

	q := clientQuery(t, "example.com", rrtype.A)
	w := &captureWriter{}
	h.ServeDNS(t.Context(), w, q)
	require.NotNil(t, w.got)
	require.Equal(t, wire.RCODEServFail, w.got.Flags().RCODE())
	require.Equal(t, int64(1), up.calls.Load())

	// SERVFAIL from a failed upstream must NOT be cached either —
	// the next call must re-issue.
	w = &captureWriter{}
	h.ServeDNS(t.Context(), w, q)
	require.Equal(t, int64(2), up.calls.Load())
}

func TestNonQueryOpcodeRejectedNotImp(t *testing.T) {
	t.Parallel()
	up := &fakeUpstream{
		handler: func(q wire.Message) wire.Message {
			return answer(q, time.Hour, netip.MustParseAddr("203.0.113.10"))
		},
	}
	h, err := forward.New(forward.WithUpstream(up))
	require.NoError(t, err)

	q, err := wire.NewBuilder().
		ID(0xbeef).
		Opcode(wire.OpcodeUpdate).
		RecursionDesired(true).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	require.NoError(t, err)

	w := &captureWriter{}
	h.ServeDNS(t.Context(), w, q)
	require.NotNil(t, w.got)
	require.Equal(t, wire.RCODENotImp, w.got.Flags().RCODE())
	require.Equal(t, uint16(0xbeef), w.got.ID())
	require.True(t, w.got.Flags().Response())
	require.Equal(t, int64(0), up.calls.Load(), "non-QUERY opcode must short-circuit before upstream")
}

func TestZeroQuestionsRejectedFormErr(t *testing.T) {
	t.Parallel()
	up := &fakeUpstream{
		handler: func(q wire.Message) wire.Message {
			return answer(q, time.Hour, netip.MustParseAddr("203.0.113.10"))
		},
	}
	h, err := forward.New(forward.WithUpstream(up))
	require.NoError(t, err)

	q, err := wire.NewBuilder().ID(0x1234).RecursionDesired(true).Build()
	require.NoError(t, err)

	w := &captureWriter{}
	h.ServeDNS(t.Context(), w, q)
	require.NotNil(t, w.got)
	require.Equal(t, wire.RCODEFormErr, w.got.Flags().RCODE())
	require.Equal(t, int64(0), up.calls.Load())
}

func TestMultipleQuestionsRejectedFormErr(t *testing.T) {
	t.Parallel()
	up := &fakeUpstream{
		handler: func(q wire.Message) wire.Message {
			return answer(q, time.Hour, netip.MustParseAddr("203.0.113.10"))
		},
	}
	h, err := forward.New(forward.WithUpstream(up))
	require.NoError(t, err)

	q, err := wire.NewBuilder().
		ID(0x1234).
		RecursionDesired(true).
		Question(wire.NewQuestion(wire.MustParseName("a.example."), rrtype.A)).
		Question(wire.NewQuestion(wire.MustParseName("b.example."), rrtype.A)).
		Build()
	require.NoError(t, err)

	w := &captureWriter{}
	h.ServeDNS(t.Context(), w, q)
	require.NotNil(t, w.got)
	require.Equal(t, wire.RCODEFormErr, w.got.Flags().RCODE())
	require.Equal(t, int64(0), up.calls.Load())
}

// TestEDNSPreservedAndForwarded verifies that EDNS on the inbound query
// is propagated to the upstream forwarded query (DO bit, UDPSize) and
// that EDNS from the upstream response is propagated back to the client.
func TestEDNSPreservedAndForwarded(t *testing.T) {
	t.Parallel()
	var sawDO atomic.Bool
	var sawUDPSize atomic.Uint32
	up := &fakeUpstream{
		handler: func(q wire.Message) wire.Message {
			if e, ok := q.EDNS(); ok {
				sawDO.Store(e.DO())
				sawUDPSize.Store(uint32(e.UDPSize()))
			}
			respEDNS := wire.NewEDNSBuilder().UDPSize(4096).DO(true).Build()
			a, _ := wire.NewBuilder().
				ID(q.ID()).
				Response(true).
				RecursionDesired(q.Flags().RecursionDesired()).
				RecursionAvailable(true).
				Question(q.Questions()[0]).
				Answer(wire.NewRecord(q.Questions()[0].Name(), 30*time.Second,
					rdata.NewA(netip.MustParseAddr("203.0.113.99")))).
				EDNS(respEDNS).
				Build()
			return a
		},
	}
	h, err := forward.New(forward.WithUpstream(up))
	require.NoError(t, err)

	clientEDNS := wire.NewEDNSBuilder().UDPSize(1232).DO(true).Build()
	q, err := wire.NewBuilder().
		ID(0xc0de).
		RecursionDesired(true).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		EDNS(clientEDNS).
		Build()
	require.NoError(t, err)

	w := &captureWriter{}
	h.ServeDNS(t.Context(), w, q)
	require.NotNil(t, w.got)
	require.True(t, sawDO.Load(), "upstream forward query must preserve DO")
	require.Equal(t, uint32(1232), sawUDPSize.Load(), "upstream forward query must preserve UDPSize")

	respEDNS, ok := w.got.EDNS()
	require.True(t, ok, "client response must include EDNS forwarded from upstream")
	require.True(t, respEDNS.DO())
	require.Equal(t, uint16(4096), respEDNS.UDPSize())
}

// TestNXDomainNoSOAFallsBackToMaxNeg covers the makeEntry NXDOMAIN
// branch where the upstream supplies no SOA — the forwarder caches
// using the configured maxNegTTL ceiling.
func TestNXDomainNoSOAFallsBackToMaxNeg(t *testing.T) {
	t.Parallel()
	up := &fakeUpstream{
		handler: func(q wire.Message) wire.Message {
			a, _ := wire.NewBuilder().
				ID(q.ID()).
				Response(true).
				RecursionDesired(q.Flags().RecursionDesired()).
				RecursionAvailable(true).
				RCODE(wire.RCODENXDomain).
				Question(q.Questions()[0]).
				Build()
			return a
		},
	}
	h, err := forward.New(
		forward.WithUpstream(up),
		forward.WithMaxNegativeTTL(time.Hour),
	)
	require.NoError(t, err)

	q := clientQuery(t, "nope.example", rrtype.A)
	for i := 0; i < 3; i++ {
		w := &captureWriter{}
		h.ServeDNS(t.Context(), w, q)
		require.Equal(t, wire.RCODENXDomain, w.got.Flags().RCODE())
	}
	require.Equal(t, int64(1), up.calls.Load(), "NXDOMAIN without SOA should still be cached at maxNegTTL")
	require.Equal(t, 1, h.CacheSize())
}

// TestNoDataNoSOANotCached covers the NoError-no-answers-no-SOA
// branch — the response is delivered but no entry is stored.
func TestNoDataNoSOANotCached(t *testing.T) {
	t.Parallel()
	up := &fakeUpstream{
		handler: func(q wire.Message) wire.Message {
			a, _ := wire.NewBuilder().
				ID(q.ID()).
				Response(true).
				RecursionDesired(q.Flags().RecursionDesired()).
				RecursionAvailable(true).
				Question(q.Questions()[0]).
				Build()
			return a
		},
	}
	h, err := forward.New(forward.WithUpstream(up))
	require.NoError(t, err)

	q := clientQuery(t, "empty.example", rrtype.A)
	for i := 0; i < 3; i++ {
		w := &captureWriter{}
		h.ServeDNS(t.Context(), w, q)
		require.Equal(t, wire.RCODENoError, w.got.Flags().RCODE())
		require.Empty(t, w.got.Answers())
	}
	require.Equal(t, int64(3), up.calls.Load(), "NoError-no-answers-no-SOA must not be cached")
	require.Equal(t, 0, h.CacheSize())
}

// TestPositiveZeroTTLNotCached forces the makeEntry "ttl <= 0" early
// return on the positive branch.
func TestPositiveZeroTTLNotCached(t *testing.T) {
	t.Parallel()
	up := &fakeUpstream{
		handler: func(q wire.Message) wire.Message {
			return answer(q, 0, netip.MustParseAddr("203.0.113.10"))
		},
	}
	h, err := forward.New(forward.WithUpstream(up))
	require.NoError(t, err)

	q := clientQuery(t, "zero.example", rrtype.A)
	for i := 0; i < 3; i++ {
		w := &captureWriter{}
		h.ServeDNS(t.Context(), w, q)
		require.Equal(t, wire.RCODENoError, w.got.Flags().RCODE())
	}
	require.Equal(t, int64(3), up.calls.Load(), "ttl=0 positive answers must bypass cache")
	require.Equal(t, 0, h.CacheSize())
}

// TestMinTTLFloor exercises the WithMinTTL option — small upstream TTLs
// are lifted to the floor so subsequent queries are cache hits.
func TestMinTTLFloor(t *testing.T) {
	t.Parallel()
	up := &fakeUpstream{
		handler: func(q wire.Message) wire.Message {
			// Upstream advertises an extremely small TTL to defeat
			// caching; with WithMinTTL we override it.
			return answer(q, time.Millisecond, netip.MustParseAddr("203.0.113.10"))
		},
	}
	h, err := forward.New(
		forward.WithUpstream(up),
		forward.WithMinTTL(10*time.Second),
	)
	require.NoError(t, err)

	q := clientQuery(t, "example.com", rrtype.A)
	for i := 0; i < 3; i++ {
		w := &captureWriter{}
		h.ServeDNS(t.Context(), w, q)
	}
	require.Equal(t, int64(1), up.calls.Load(), "min-TTL floor must keep entry alive across rapid lookups")
}

// TestMaxTTLCap exercises the WithMaxTTL option — a huge upstream TTL
// is clamped down so the cache entry expires per the cap. The served
// per-record TTL is the upstream's (the cap governs cache lifetime).
func TestMaxTTLCap(t *testing.T) {
	t.Parallel()
	up := &fakeUpstream{
		handler: func(q wire.Message) wire.Message {
			return answer(q, 7*24*time.Hour, netip.MustParseAddr("203.0.113.10"))
		},
	}
	clk := newFakeClock()
	h, err := forward.New(
		forward.WithUpstream(up),
		forward.WithMaxTTL(time.Second),
		forward.WithNowFunc(clk.Now),
	)
	require.NoError(t, err)

	q := clientQuery(t, "example.com", rrtype.A)
	w := &captureWriter{}
	h.ServeDNS(t.Context(), w, q)
	require.Equal(t, int64(1), up.calls.Load())

	// Within the cap window the cache should still be hot.
	w = &captureWriter{}
	h.ServeDNS(t.Context(), w, q)
	require.Equal(t, int64(1), up.calls.Load())

	// After the cap, the entry must expire even though the upstream
	// TTL was a week.
	clk.Advance(2 * time.Second)
	w = &captureWriter{}
	h.ServeDNS(t.Context(), w, q)
	require.Equal(t, int64(2), up.calls.Load(),
		"WithMaxTTL must cap cache lifetime regardless of upstream TTL")
}

// TestQueryTimeoutAppliesWhenNoDeadline ensures WithQueryTimeout adds a
// deadline to upstream context when the inbound has none.
func TestQueryTimeoutAppliesWhenNoDeadline(t *testing.T) {
	t.Parallel()
	var sawDeadline atomic.Bool
	up := &fakeUpstream{
		handler: func(q wire.Message) wire.Message {
			return answer(q, time.Hour, netip.MustParseAddr("203.0.113.10"))
		},
	}
	// Wrap in an Exchanger that inspects the context.
	wrapped := &deadlineSpyExchanger{inner: up, sawDeadline: &sawDeadline}

	h, err := forward.New(
		forward.WithUpstream(wrapped),
		forward.WithQueryTimeout(50*time.Millisecond),
	)
	require.NoError(t, err)

	q := clientQuery(t, "example.com", rrtype.A)
	w := &captureWriter{}
	h.ServeDNS(t.Context(), w, q) // no deadline on parent
	require.True(t, sawDeadline.Load(), "WithQueryTimeout should attach a deadline to upstream context")
}

type deadlineSpyExchanger struct {
	inner       acidns.Exchanger
	sawDeadline *atomic.Bool
}

func (d *deadlineSpyExchanger) Exchange(ctx context.Context, q wire.Message) (wire.Message, error) {
	if _, ok := ctx.Deadline(); ok {
		d.sawDeadline.Store(true)
	}
	return d.inner.Exchange(ctx, q)
}

// TestExistingDeadlineNotOverridden verifies the queryTimeout branch is
// skipped when the caller's context already has a deadline.
func TestExistingDeadlineNotOverridden(t *testing.T) {
	t.Parallel()
	up := &fakeUpstream{
		handler: func(q wire.Message) wire.Message {
			return answer(q, time.Hour, netip.MustParseAddr("203.0.113.10"))
		},
	}
	h, err := forward.New(
		forward.WithUpstream(up),
		forward.WithQueryTimeout(time.Hour),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(2*time.Second))
	defer cancel()

	w := &captureWriter{}
	h.ServeDNS(ctx, w, clientQuery(t, "example.com", rrtype.A))
	require.NotNil(t, w.got)
	require.Equal(t, wire.RCODENoError, w.got.Flags().RCODE())
}

// TestCacheReplacesExisting hits the cache.put path that updates an
// existing entry in place (rather than inserting a new one). We achieve
// that by having the upstream return responses whose makeEntry rebuilds
// for the same key after the first entry has expired.
func TestCacheReplacesExisting(t *testing.T) {
	t.Parallel()
	var counter atomic.Int32
	up := &fakeUpstream{
		handler: func(q wire.Message) wire.Message {
			counter.Add(1)
			return answer(q, time.Second, netip.MustParseAddr("203.0.113.10"))
		},
	}
	clk := newFakeClock()
	h, err := forward.New(forward.WithUpstream(up), forward.WithNowFunc(clk.Now))
	require.NoError(t, err)

	q := clientQuery(t, "example.com", rrtype.A)
	w := &captureWriter{}
	h.ServeDNS(t.Context(), w, q)
	require.Equal(t, 1, h.CacheSize())

	clk.Advance(2 * time.Second)
	w = &captureWriter{}
	h.ServeDNS(t.Context(), w, q)
	require.Equal(t, int64(2), up.calls.Load())
	require.Equal(t, 1, h.CacheSize(), "replacing an expired entry should leave cache size unchanged")
}

// TestCacheEvictsLRU forces the LRU back-eviction path in cache.put.
func TestCacheEvictsLRU(t *testing.T) {
	t.Parallel()
	up := &fakeUpstream{
		handler: func(q wire.Message) wire.Message {
			return answer(q, time.Hour, netip.MustParseAddr("203.0.113.10"))
		},
	}
	h, err := forward.New(
		forward.WithUpstream(up),
		forward.WithCacheSize(2),
	)
	require.NoError(t, err)

	for _, name := range []string{"a.example.", "b.example.", "c.example."} {
		w := &captureWriter{}
		h.ServeDNS(t.Context(), w, clientQuery(t, name, rrtype.A))
	}
	require.Equal(t, 2, h.CacheSize(), "cache must not exceed configured capacity")
	require.Equal(t, int64(3), up.calls.Load())

	// "a.example." should have been evicted; querying it again must
	// hit the upstream a fourth time.
	w := &captureWriter{}
	h.ServeDNS(t.Context(), w, clientQuery(t, "a.example.", rrtype.A))
	require.Equal(t, int64(4), up.calls.Load(), "evicted entry must require re-fetch")
}

// TestUDPTCPFallbackOnTruncated stands up a UDP server that sets TC=1
// and a TCP server that returns a real answer; the upstream wrapper
// must fall back to TCP per RFC 1035 §4.2.1.
func TestUDPTCPFallbackOnTruncated(t *testing.T) {
	t.Parallel()
	udpHandler := acidns.HandlerFunc(func(_ context.Context, w acidns.ResponseWriter, q wire.Message) {
		// Build a truncated empty response.
		m, _ := wire.NewBuilder().
			ID(q.ID()).
			Response(true).
			RecursionDesired(q.Flags().RecursionDesired()).
			RecursionAvailable(true).
			Truncated(true).
			Question(q.Questions()[0]).
			Build()
		_ = w.WriteMsg(m)
	})
	tcpHandler := acidns.HandlerFunc(func(_ context.Context, w acidns.ResponseWriter, q wire.Message) {
		_ = w.WriteMsg(answer(q, 30*time.Second, netip.MustParseAddr("198.51.100.42")))
	})
	udpSrv, err := acidns.ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"), udpHandler)
	require.NoError(t, err)
	tcpSrv, err := acidns.ListenTCP(udpSrv.Addr(), tcpHandler)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = udpSrv.Serve(ctx) }()
	go func() { _ = tcpSrv.Serve(ctx) }()

	h, err := forward.New(forward.WithUDPUpstream(udpSrv.Addr()))
	require.NoError(t, err)

	w := &captureWriter{}
	h.ServeDNS(t.Context(), w, clientQuery(t, "trunc.example.", rrtype.A))
	require.NotNil(t, w.got)
	require.Equal(t, wire.RCODENoError, w.got.Flags().RCODE())
	require.Len(t, w.got.Answers(), 1, "TCP-fallback answer should reach the client")
	require.False(t, w.got.Flags().Truncated(), "client response must not be marked truncated")
}

// TestUDPUpstreamUDPDialFailure points the UDP upstream at an
// unspecified zero address — both UDPExchanger and TCPExchanger should
// reject it, surfacing the construction error via errExchanger on first
// Exchange.
func TestUDPUpstreamConstructionFailureSurfacedAsServFail(t *testing.T) {
	t.Parallel()
	// AddrPort{} is the zero value (invalid). NewUDPExchanger refuses
	// it, leaving the forwarder configured with an errExchanger.
	h, err := forward.New(forward.WithUDPUpstream(netip.AddrPort{}))
	require.NoError(t, err, "construction errors are deferred to first Exchange")

	w := &captureWriter{}
	h.ServeDNS(t.Context(), w, clientQuery(t, "example.com", rrtype.A))
	require.NotNil(t, w.got)
	require.Equal(t, wire.RCODEServFail, w.got.Flags().RCODE(),
		"errExchanger error must propagate as SERVFAIL")
}

// TestWithDoTUpstreamServerName configures the DoT upstream — actual
// network exchange is not driven (no DoT server here); we only verify
// that the option wires successfully and surfaces a label.
func TestWithDoTUpstreamServerName(t *testing.T) {
	t.Parallel()
	addr := netip.MustParseAddrPort("127.0.0.1:853")
	h, err := forward.New(forward.WithDoTUpstream(addr, "dns.example."))
	require.NoError(t, err)
	require.Contains(t, h.UpstreamName(), "tls://")
	require.Contains(t, h.UpstreamName(), addr.String())
}

func TestWithDoTUpstreamServerNameInvalidAddr(t *testing.T) {
	t.Parallel()
	// dot.New rejects invalid addresses; the option records this as
	// errExchanger so first ServeDNS returns SERVFAIL.
	h, err := forward.New(forward.WithDoTUpstream(netip.AddrPort{}, "dns.example."))
	require.NoError(t, err)
	require.Equal(t, "(invalid dot)", h.UpstreamName())

	w := &captureWriter{}
	h.ServeDNS(t.Context(), w, clientQuery(t, "example.com", rrtype.A))
	require.Equal(t, wire.RCODEServFail, w.got.Flags().RCODE())
}

func TestWithDoTUpstreamTLSConfig(t *testing.T) {
	t.Parallel()
	addr := netip.MustParseAddrPort("127.0.0.1:853")
	tc := &tls.Config{ServerName: "dns.example.", MinVersion: tls.VersionTLS13}
	h, err := forward.New(forward.WithDoTUpstreamTLSConfig(addr, tc))
	require.NoError(t, err)
	require.Contains(t, h.UpstreamName(), "tls://")
}

func TestWithDoTUpstreamTLSConfigInvalidAddr(t *testing.T) {
	t.Parallel()
	tc := &tls.Config{ServerName: "dns.example."}
	h, err := forward.New(forward.WithDoTUpstreamTLSConfig(netip.AddrPort{}, tc))
	require.NoError(t, err)
	require.Equal(t, "(invalid dot)", h.UpstreamName())

	w := &captureWriter{}
	h.ServeDNS(t.Context(), w, clientQuery(t, "example.com", rrtype.A))
	require.Equal(t, wire.RCODEServFail, w.got.Flags().RCODE())
}

// TestNegativeTTLFromSOATTLLowerThanMinimum exercises the
// negativeTTLFromSOA branch where the SOA record's own TTL is lower
// than the SOA MINIMUM field — the code picks the smaller of the two
// per RFC 2308 §5.
func TestNegativeTTLFromSOATTLLowerThanMinimum(t *testing.T) {
	t.Parallel()
	up := &fakeUpstream{
		handler: func(q wire.Message) wire.Message {
			// SOA TTL is 1s (small), MINIMUM is 1 hour (large) — the
			// cached negative entry should expire after the SOA TTL.
			return nxdomain(q, time.Second, time.Hour)
		},
	}
	clk := newFakeClock()
	h, err := forward.New(
		forward.WithUpstream(up),
		forward.WithMaxNegativeTTL(time.Hour), // ensure no other cap interferes
		forward.WithNowFunc(clk.Now),
	)
	require.NoError(t, err)

	q := clientQuery(t, "nope.example", rrtype.A)
	w := &captureWriter{}
	h.ServeDNS(t.Context(), w, q)
	require.Equal(t, int64(1), up.calls.Load())

	clk.Advance(2 * time.Second)
	w = &captureWriter{}
	h.ServeDNS(t.Context(), w, q)
	require.Equal(t, int64(2), up.calls.Load(),
		"negative cache must expire when SOA-record TTL is the binding cap")
}
