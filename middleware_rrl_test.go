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

type rrlCapturingWriter struct {
	src      netip.AddrPort
	captured wire.Message
	written  bool
}

func (w *rrlCapturingWriter) WriteMsg(m wire.Message) error {
	w.captured = m
	w.written = true
	return nil
}
func (w *rrlCapturingWriter) RemoteAddr() netip.AddrPort { return w.src }
func (*rrlCapturingWriter) LocalAddr() netip.AddrPort    { return netip.AddrPort{} }
func (*rrlCapturingWriter) Network() string              { return netUDP }

func rrlPositiveAnswer() acidns.Handler {
	return acidns.HandlerFunc(func(_ context.Context, w acidns.ResponseWriter, q wire.Message) {
		ans := wire.NewRecord(q.Questions()[0].Name(), 60*time.Second,
			rdata.MustNewA(netip.MustParseAddr("203.0.113.7")))
		resp, _ := wire.NewMessageBuilder().
			ID(q.ID()).
			Response(true).
			Question(q.Questions()[0]).
			Answer(ans).
			Build()
		_ = w.WriteMsg(resp)
	})
}

func rrlNXDomain() acidns.Handler {
	return acidns.HandlerFunc(func(_ context.Context, w acidns.ResponseWriter, q wire.Message) {
		resp, _ := wire.NewMessageBuilder().
			ID(q.ID()).
			Response(true).
			Question(q.Questions()[0]).
			RCODE(wire.RCODENXDomain).
			Build()
		_ = w.WriteMsg(resp)
	})
}

func rrlQuery(t *testing.T, name string) wire.Message {
	t.Helper()
	q, err := wire.NewMessageBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName(name), rrtype.A)).
		Build()
	require.NoError(t, err)
	return q
}

func TestRRLAllowsUntilBudgetExhausted(t *testing.T) {
	t.Parallel()
	h := acidns.NewRRL(rrlPositiveAnswer(),
		acidns.WithRRLQPS(0.0001), // refill effectively never
		acidns.WithRRLBurst(3),
		acidns.WithRRLSlipRate(0), // always drop on overage so we can measure
	)

	src := netip.MustParseAddrPort("203.0.113.50:1")
	for i := range 3 {
		w := &rrlCapturingWriter{src: src}
		h.ServeDNS(context.Background(), w, rrlQuery(t, "victim.example."))
		require.True(t, w.written, "first %d responses should pass", i+1)
		require.False(t, w.captured.Flags().Truncated())
	}

	// 4th: dropped silently because slip=0.
	w := &rrlCapturingWriter{src: src}
	h.ServeDNS(context.Background(), w, rrlQuery(t, "victim.example."))
	require.False(t, w.written, "over-budget response must be dropped when slip=0")
}

func TestRRLSlipsBlockedResponseAsTruncation(t *testing.T) {
	t.Parallel()
	h := acidns.NewRRL(rrlPositiveAnswer(),
		acidns.WithRRLQPS(0.0001),
		acidns.WithRRLBurst(1),
		acidns.WithRRLSlipRate(2), // every other blocked → TC
	)

	src := netip.MustParseAddrPort("203.0.113.51:1")

	// Burn the burst.
	w0 := &rrlCapturingWriter{src: src}
	h.ServeDNS(context.Background(), w0, rrlQuery(t, "victim.example."))
	require.True(t, w0.written)
	require.False(t, w0.captured.Flags().Truncated())

	// First over-budget: dropped.
	w1 := &rrlCapturingWriter{src: src}
	h.ServeDNS(context.Background(), w1, rrlQuery(t, "victim.example."))
	require.False(t, w1.written, "first over-budget at slip=2 must drop")

	// Second over-budget: slipped through with TC=1.
	w2 := &rrlCapturingWriter{src: src}
	h.ServeDNS(context.Background(), w2, rrlQuery(t, "victim.example."))
	require.True(t, w2.written, "second over-budget at slip=2 must slip")
	require.True(t, w2.captured.Flags().Truncated(),
		"slipped response must have TC=1 so client retries over TCP")
}

func TestRRLSegregatesByResponseName(t *testing.T) {
	t.Parallel()
	h := acidns.NewRRL(rrlPositiveAnswer(),
		acidns.WithRRLQPS(0.0001),
		acidns.WithRRLBurst(1),
		acidns.WithRRLSlipRate(0),
	)

	src := netip.MustParseAddrPort("203.0.113.52:1")

	// Burst budget for "a.example.".
	wa := &rrlCapturingWriter{src: src}
	h.ServeDNS(context.Background(), wa, rrlQuery(t, "a.example."))
	require.True(t, wa.written)

	// "b.example." has its own bucket.
	wb := &rrlCapturingWriter{src: src}
	h.ServeDNS(context.Background(), wb, rrlQuery(t, "b.example."))
	require.True(t, wb.written, "different response name must use a separate bucket")
}

func TestRRLSegregatesByClass(t *testing.T) {
	t.Parallel()
	// A handler that answers half NXDomain and half positive.
	pos := rrlPositiveAnswer()
	neg := rrlNXDomain()

	h := acidns.NewRRL(acidns.HandlerFunc(func(ctx context.Context, w acidns.ResponseWriter, q wire.Message) {
		if q.Questions()[0].Name().String() == "neg.example." {
			neg.ServeDNS(ctx, w, q)
			return
		}
		pos.ServeDNS(ctx, w, q)
	}),
		acidns.WithRRLQPS(0.0001),
		acidns.WithRRLNXDOMAINQPS(0.0001),
		acidns.WithRRLBurst(1),
		acidns.WithRRLSlipRate(0),
	)

	src := netip.MustParseAddrPort("203.0.113.53:1")

	// Burn positive bucket on a.example.
	w1 := &rrlCapturingWriter{src: src}
	h.ServeDNS(context.Background(), w1, rrlQuery(t, "a.example."))
	require.True(t, w1.written)

	// NXDomain on neg.example uses a separate (negative-class) bucket.
	w2 := &rrlCapturingWriter{src: src}
	h.ServeDNS(context.Background(), w2, rrlQuery(t, "neg.example."))
	require.True(t, w2.written, "negative-class responses bucket separately from positive")
	require.Equal(t, wire.RCODENXDomain, w2.captured.Flags().RCODE())
}

func TestRRLAggregatesByPrefix(t *testing.T) {
	t.Parallel()
	h := acidns.NewRRL(rrlPositiveAnswer(),
		acidns.WithRRLQPS(0.0001),
		acidns.WithRRLBurst(1),
		acidns.WithRRLSlipRate(0),
		acidns.WithRRLIPv4Prefix(24),
	)

	// Two sources within the same /24 share a bucket.
	w1 := &rrlCapturingWriter{src: netip.MustParseAddrPort("198.51.100.10:1")}
	h.ServeDNS(context.Background(), w1, rrlQuery(t, "victim.example."))
	require.True(t, w1.written)

	w2 := &rrlCapturingWriter{src: netip.MustParseAddrPort("198.51.100.20:1")}
	h.ServeDNS(context.Background(), w2, rrlQuery(t, "victim.example."))
	require.False(t, w2.written,
		"second source in same /24 should share the exhausted bucket")
}
