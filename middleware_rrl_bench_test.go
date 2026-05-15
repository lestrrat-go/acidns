package acidns_test

// Benchmarks for the RRL middleware's bucket-map shape. Mirror analysis
// of middleware_ratelimit_bench_test.go's tradeoff for the response-
// rate-limiting layer.
//
// Summary (AMD Ryzen 9 7900X3D, Go default GC):
//
//   variant            path              ns/op   allocs/op   bytes/op
//   --------           -----------       -----   ---------   --------
//   *rrlBucket (kept)  SaturatedNewKey   3260    14          711
//   rrlBucket          SaturatedNewKey   3290    13          663
//   *rrlBucket (kept)  HotKey            450     9           472
//   rrlBucket          HotKey            470     9           472
//
// The per-new-key alloc reduction (14→13, ~7%) is smaller than the
// rate-limiter's equivalent (3→2, ~33%) because the RRL hot path does
// more inherent work (classify, qname extraction, source key build).
// The HotKey regression of ~20 ns/op is small in absolute terms but is
// paid by every legitimate response forever. Pointer-typed kept; see
// the Shard struct comment in internal/shardbucket/shardbucket.go.

import (
	"context"
	"net/netip"
	"testing"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// BenchmarkRRLSaturatedNewKey measures the cost of consume() when the
// RRL limiter is at its per-shard cap and every response is keyed under
// a new (source, name) tuple — the random-subdomain flood path.
func BenchmarkRRLSaturatedNewKey(b *testing.B) {
	// Inner handler emits a NoError answer the RRL rates as "positive".
	inner := acidns.HandlerFunc(func(_ context.Context, w acidns.ResponseWriter, q wire.Message) {
		ar, _ := rdata.NewA(netip.MustParseAddr("203.0.113.42"))
		ans := wire.NewRecord(q.Questions()[0].Name(), 0, ar)
		resp, _ := wire.NewMessageBuilder().
			ID(q.ID()).
			Response(true).
			Question(q.Questions()[0]).
			Answer(ans).
			Build()
		_ = w.WriteMsg(resp)
	})
	h := acidns.NewRRL(inner,
		acidns.WithRRLQPS(1e6),
		acidns.WithRRLBurst(1),
		acidns.WithRRLMaxKeys(6400),
	)

	ctx := b.Context()

	// Warm the shards to cap.
	for i := range 100_000 {
		w := &rlBenchWriter{src: ipForIndex(i)}
		h.ServeDNS(ctx, w, rrlBenchQuery(b, i))
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := range b.N {
		w := &rlBenchWriter{src: ipForIndex(100_000 + i)}
		h.ServeDNS(ctx, w, rrlBenchQuery(b, 100_000+i))
	}
}

// BenchmarkRRLHotKey measures the steady-state path: same source, same
// response name on every call. No eviction, no new-key insert.
func BenchmarkRRLHotKey(b *testing.B) {
	inner := acidns.HandlerFunc(func(_ context.Context, w acidns.ResponseWriter, q wire.Message) {
		ar, _ := rdata.NewA(netip.MustParseAddr("203.0.113.42"))
		ans := wire.NewRecord(q.Questions()[0].Name(), 0, ar)
		resp, _ := wire.NewMessageBuilder().
			ID(q.ID()).
			Response(true).
			Question(q.Questions()[0]).
			Answer(ans).
			Build()
		_ = w.WriteMsg(resp)
	})
	h := acidns.NewRRL(inner,
		acidns.WithRRLQPS(1e9),
		acidns.WithRRLBurst(1_000_000),
	)
	ctx := b.Context()
	src := netip.MustParseAddrPort("203.0.113.42:1")
	q := rrlBenchQuery(b, 0)

	// Warmup.
	h.ServeDNS(ctx, &rlBenchWriter{src: src}, q)

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		h.ServeDNS(ctx, &rlBenchWriter{src: src}, q)
	}
}

func rrlBenchQuery(b *testing.B, i int) wire.Message {
	b.Helper()
	// Per-iteration qname so each query lands under a fresh (src, name)
	// bucket in the saturated benchmark.
	name := wire.MustParseName("rand-" + intToHex(i) + ".victim.example.com.")
	q, err := wire.NewMessageBuilder().
		ID(1).
		Question(wire.NewQuestion(name, rrtype.A)).
		Build()
	if err != nil {
		b.Fatal(err)
	}
	return q
}

func intToHex(n int) string {
	const hex = "0123456789abcdef"
	// up to 8 nibbles is plenty for benchmark indices.
	var out [8]byte
	for i := range 8 {
		out[7-i] = hex[n&0xf]
		n >>= 4
	}
	return string(out[:])
}
