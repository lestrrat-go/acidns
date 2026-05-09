package acidns_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

type rlFakeWriter struct {
	src      netip.AddrPort
	captured wire.Message
	written  bool
}

func (w *rlFakeWriter) WriteMsg(m wire.Message) error {
	w.captured = m
	w.written = true
	return nil
}
func (w *rlFakeWriter) RemoteAddr() netip.AddrPort { return w.src }
func (w *rlFakeWriter) LocalAddr() netip.AddrPort  { return netip.AddrPort{} }
func (w *rlFakeWriter) Network() string            { return "udp" }

func rateLimitMkInner() acidns.Handler {
	return acidns.HandlerFunc(func(_ context.Context, w acidns.ResponseWriter, q wire.Message) {
		ans := wire.NewRecord(q.Questions()[0].Name(), time.Minute,
			rdata.MustNewA(netip.MustParseAddr("203.0.113.1")))
		resp, _ := wire.NewBuilder().
			ID(q.ID()).
			Response(true).
			Question(q.Questions()[0]).
			Answer(ans).
			Build()
		_ = w.WriteMsg(resp)
	})
}

func rateLimitMkQuery(t *testing.T) wire.Message {
	t.Helper()
	q, err := wire.NewBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	require.NoError(t, err)
	return q
}

func TestRateLimitBurstThenRefuse(t *testing.T) {
	t.Parallel()

	h := acidns.NewRateLimit(rateLimitMkInner(),
		acidns.WithRateLimitQPS(0.0001), // refill almost never within the test
		acidns.WithRateLimitBurst(3),
	)

	for i := range 3 {
		w := &rlFakeWriter{src: netip.MustParseAddrPort("198.51.100.5:1000")}
		h.ServeDNS(context.Background(), w, rateLimitMkQuery(t))
		require.Equal(t, wire.RCODENoError, w.captured.Flags().RCODE(),
			"first %d should pass through", i+1)
	}

	w := &rlFakeWriter{src: netip.MustParseAddrPort("198.51.100.5:1000")}
	h.ServeDNS(context.Background(), w, rateLimitMkQuery(t))
	require.Equal(t, wire.RCODERefused, w.captured.Flags().RCODE())
}

func TestRateLimitPerSourceIndependent(t *testing.T) {
	t.Parallel()
	h := acidns.NewRateLimit(rateLimitMkInner(), acidns.WithRateLimitQPS(0.0001), acidns.WithRateLimitBurst(1))

	w1 := &rlFakeWriter{src: netip.MustParseAddrPort("203.0.113.1:1")}
	h.ServeDNS(context.Background(), w1, rateLimitMkQuery(t))
	require.Equal(t, wire.RCODENoError, w1.captured.Flags().RCODE())

	// First query from a different source must succeed regardless of the
	// other's exhausted bucket.
	w2 := &rlFakeWriter{src: netip.MustParseAddrPort("203.0.113.2:1")}
	h.ServeDNS(context.Background(), w2, rateLimitMkQuery(t))
	require.Equal(t, wire.RCODENoError, w2.captured.Flags().RCODE())
}

func TestRateLimitDrop(t *testing.T) {
	t.Parallel()
	h := acidns.NewRateLimit(rateLimitMkInner(),
		acidns.WithRateLimitQPS(0.0001), acidns.WithRateLimitBurst(1), acidns.WithRateLimitDrop())

	w := &rlFakeWriter{src: netip.MustParseAddrPort("203.0.113.10:1")}
	h.ServeDNS(context.Background(), w, rateLimitMkQuery(t)) // first OK
	require.True(t, w.written)

	w2 := &rlFakeWriter{src: netip.MustParseAddrPort("203.0.113.10:1")}
	h.ServeDNS(context.Background(), w2, rateLimitMkQuery(t)) // second dropped
	require.False(t, w2.written, "drop mode must not write a response")
}

func TestRateLimitGroupPrefix(t *testing.T) {
	t.Parallel()
	// /24 grouping means 198.51.100.1 and 198.51.100.2 share a bucket.
	h := acidns.NewRateLimit(rateLimitMkInner(),
		acidns.WithRateLimitQPS(0.0001),
		acidns.WithRateLimitBurst(1),
		acidns.WithRateLimitGroupPrefix(24),
	)

	w1 := &rlFakeWriter{src: netip.MustParseAddrPort("198.51.100.1:1")}
	h.ServeDNS(context.Background(), w1, rateLimitMkQuery(t))
	require.Equal(t, wire.RCODENoError, w1.captured.Flags().RCODE())

	w2 := &rlFakeWriter{src: netip.MustParseAddrPort("198.51.100.2:1")}
	h.ServeDNS(context.Background(), w2, rateLimitMkQuery(t))
	require.Equal(t, wire.RCODERefused, w2.captured.Flags().RCODE(),
		"second source in same /24 should share the exhausted bucket")
}

func TestRateLimitMaxKeysCap(t *testing.T) {
	t.Parallel()

	// MaxKeys is sharded across 64 buckets (ceil(n/64) per shard);
	// pick a global cap that yields a meaningful per-shard cap and
	// then verify the total stays within the multi-shard ceiling.
	const limit = 640
	const numShards = 64
	const perShardCap = (limit + numShards - 1) / numShards
	const ceiling = perShardCap * numShards

	h := acidns.NewRateLimit(rateLimitMkInner(),
		acidns.WithRateLimitQPS(0.0001),
		acidns.WithRateLimitBurst(1),
		acidns.WithRateLimitMaxKeys(limit),
	)

	// Fire from many distinct sources; the limiter must never grow above
	// the per-shard ceiling summed across shards.
	for i := range 4 * limit {
		ip := [4]byte{
			198,
			51,
			byte((i >> 8) & 0xff),
			byte(i & 0xff),
		}
		src := netip.AddrPortFrom(netip.AddrFrom4(ip), 1)
		w := &rlFakeWriter{src: src}
		h.ServeDNS(context.Background(), w, rateLimitMkQuery(t))
	}

	n := acidns.RateLimitDebugLen(h)
	require.LessOrEqual(t, n, ceiling,
		"map must be bounded by per-shard cap; got %d, ceiling %d", n, ceiling)
}

func TestRateLimitRefillOverTime(t *testing.T) {
	t.Parallel()
	h := acidns.NewRateLimit(rateLimitMkInner(),
		acidns.WithRateLimitQPS(50),
		acidns.WithRateLimitBurst(1),
	)

	w1 := &rlFakeWriter{src: netip.MustParseAddrPort("203.0.113.20:1")}
	h.ServeDNS(context.Background(), w1, rateLimitMkQuery(t)) // burst
	require.Equal(t, wire.RCODENoError, w1.captured.Flags().RCODE())

	w2 := &rlFakeWriter{src: netip.MustParseAddrPort("203.0.113.20:1")}
	h.ServeDNS(context.Background(), w2, rateLimitMkQuery(t)) // immediately after
	require.Equal(t, wire.RCODERefused, w2.captured.Flags().RCODE())

	time.Sleep(40 * time.Millisecond) // 50qps → 2 tokens accumulated

	w3 := &rlFakeWriter{src: netip.MustParseAddrPort("203.0.113.20:1")}
	h.ServeDNS(context.Background(), w3, rateLimitMkQuery(t))
	require.Equal(t, wire.RCODENoError, w3.captured.Flags().RCODE(),
		"after refill the bucket should permit again")
}
