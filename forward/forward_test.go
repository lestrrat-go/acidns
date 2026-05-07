package forward_test

import (
	"context"
	"net/netip"
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
	h, err := forward.New(forward.WithUpstream(upstream))
	require.NoError(t, err)

	q := clientQuery(t, "example.com", rrtype.A)
	w1 := &captureWriter{}
	h.ServeDNS(t.Context(), w1, q)
	first := w1.got.Answers()[0].TTL()

	time.Sleep(50 * time.Millisecond)
	w2 := &captureWriter{}
	h.ServeDNS(t.Context(), w2, q)
	second := w2.got.Answers()[0].TTL()

	require.Less(t, second, first, "TTL on the cached response should decrement")
}

func TestPositiveCacheExpires(t *testing.T) {
	t.Parallel()
	upstream := &fakeUpstream{
		handler: func(q wire.Message) wire.Message {
			return answer(q, 50*time.Millisecond, netip.MustParseAddr("203.0.113.10"))
		},
	}
	h, err := forward.New(forward.WithUpstream(upstream))
	require.NoError(t, err)

	q := clientQuery(t, "example.com", rrtype.A)
	w := &captureWriter{}
	h.ServeDNS(t.Context(), w, q)
	require.Equal(t, int64(1), upstream.calls.Load())

	time.Sleep(80 * time.Millisecond)
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
	h, err := forward.New(
		forward.WithUpstream(upstream),
		forward.WithMaxNegativeTTL(80*time.Millisecond),
	)
	require.NoError(t, err)

	q := clientQuery(t, "nope.example", rrtype.A)
	w := &captureWriter{}
	h.ServeDNS(t.Context(), w, q)
	require.Equal(t, int64(1), upstream.calls.Load())

	time.Sleep(120 * time.Millisecond)
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
