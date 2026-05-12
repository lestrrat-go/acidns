package acidns_test

// Benchmarks for the rate-limit middleware's bucket-map shape.
//
// These pin a documented tradeoff: the per-source limiter uses a
// map[string]*bucket (pointer-typed). A value-typed map[string]bucket
// alternative was prototyped and benchmarked; the result is recorded on
// the limiterShard struct comment in middleware_ratelimit.go.
//
// Summary of the prior comparison (AMD Ryzen 9 7900X3D, Go default GC):
//
//   variant          path              ns/op   allocs/op   bytes/op
//   --------         -----------       -----   ---------   --------
//   *bucket (kept)   SaturatedNewKey   2270    3           79
//   bucket           SaturatedNewKey   2160    2           47
//   *bucket (kept)   HotKey            92      2           48
//   bucket           HotKey            104     2           48
//
// Pointer-typed kept because the HotKey path (legitimate steady-state
// traffic) dominates and a 13% regression there is not worth a single
// allocation eliminated on a path that's already paying ~2 µs per
// request. The value-typed alternative remains available as a two-line
// change if a production deployment ever profiles GC pressure under
// sustained spoofed-source flood.

import (
	"context"
	"net/netip"
	"testing"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// BenchmarkRateLimitSaturatedNewKey measures the cost of allow() when the
// limiter is at its per-shard cap and every incoming request introduces a
// new key — the spoofed-source-flood path. Each iteration triggers
// eviction once the cap is reached.
//
// Run with: go test -bench=BenchmarkRateLimit -benchmem -count=5 -benchtime=2s
//
// The interesting numbers:
//   - allocs/op — a value-typed map should be 0 allocs once warmed;
//     a *bucket map allocates 1/op on insert.
//   - ns/op — eviction-scan cost dominates the tail. Drops if the algorithm
//     gets cheaper; should be roughly flat if the bottleneck is elsewhere.
func BenchmarkRateLimitSaturatedNewKey(b *testing.B) {
	// Burst=1 / QPS=infinity so every distinct source gets exactly one
	// token, every request to a NEW key consumes that one token, and the
	// shard fills with cap-many keys. After that, each new key triggers
	// eviction.
	h := acidns.NewRateLimit(acidns.HandlerFunc(func(_ context.Context, _ acidns.ResponseWriter, _ wire.Message) {}),
		acidns.WithRateLimitQPS(1e6),
		acidns.WithRateLimitBurst(1),
		// Tight cap so eviction kicks in early in b.N. 64 shards × 100
		// per-shard cap = 6400 total keys (default 100K would mask the
		// eviction cost across many iterations).
		acidns.WithRateLimitMaxKeys(6400),
	)

	ctx := b.Context()
	q := benchRLQuery(b)

	// Warm the shards to cap before timing.
	for i := range 100_000 {
		w := &rlBenchWriter{src: ipForIndex(i)}
		h.ServeDNS(ctx, w, q)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := range b.N {
		w := &rlBenchWriter{src: ipForIndex(100_000 + i)}
		h.ServeDNS(ctx, w, q)
	}
}

// BenchmarkRateLimitHotKey measures the cost of allow() against an existing
// key — the steady-state path. No eviction, no allocation; just the
// token-math + map read/write.
func BenchmarkRateLimitHotKey(b *testing.B) {
	h := acidns.NewRateLimit(acidns.HandlerFunc(func(_ context.Context, _ acidns.ResponseWriter, _ wire.Message) {}),
		acidns.WithRateLimitQPS(1e9),
		acidns.WithRateLimitBurst(1_000_000),
	)
	ctx := b.Context()
	q := benchRLQuery(b)
	src := netip.MustParseAddrPort("203.0.113.42:1")

	// One warmup to create the bucket.
	h.ServeDNS(ctx, &rlBenchWriter{src: src}, q)

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		w := &rlBenchWriter{src: src}
		h.ServeDNS(ctx, w, q)
	}
}

type rlBenchWriter struct{ src netip.AddrPort }

func (w *rlBenchWriter) WriteMsg(wire.Message) error { return nil }
func (w *rlBenchWriter) RemoteAddr() netip.AddrPort  { return w.src }
func (w *rlBenchWriter) LocalAddr() netip.AddrPort   { return netip.AddrPort{} }
func (w *rlBenchWriter) Network() string             { return netUDP }

func benchRLQuery(b *testing.B) wire.Message {
	b.Helper()
	q, err := wire.NewMessageBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	if err != nil {
		b.Fatal(err)
	}
	return q
}

// ipForIndex maps a monotonic counter to a synthetic /32 source for the
// rate-limiter benchmark. 198.51.100.0/22 documentation-prefix space gives
// us 1024 IPs; we wrap into 198.51.96.0/20 (4096) and beyond by encoding
// the counter across the last two octets and bumping the third when we
// roll over. Sources are unique within the benchmark's range.
func ipForIndex(i int) netip.AddrPort {
	// 10.0.0.0/8 — private range, plenty of addresses.
	a := byte(10)
	b := byte(i >> 16 & 0xff)
	c := byte(i >> 8 & 0xff)
	d := byte(i & 0xff)
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{a, b, c, d}), 1)
}
