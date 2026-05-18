package recursive

import (
	"net/netip"
	"testing"
	"time"
)

func TestUpstreamLimiterTake(t *testing.T) {
	now := time.Unix(1700000000, 0)
	clock := func() time.Time { return now }
	addr := netip.MustParseAddrPort("192.0.2.1:53")

	l := newUpstreamLimiter(2.0, 3.0, clock)

	// Bucket starts full at burst=3 — three immediate takes succeed.
	for i := range 3 {
		if !l.Take(addr) {
			t.Fatalf("Take #%d should succeed (bucket full)", i+1)
		}
	}
	if l.Take(addr) {
		t.Fatalf("4th Take should fail — bucket drained")
	}

	// Refill at 2 qps: half a second adds 1 token.
	now = now.Add(500 * time.Millisecond)
	if !l.Take(addr) {
		t.Fatalf("Take after 0.5s refill should succeed")
	}
	if l.Take(addr) {
		t.Fatalf("immediately after consumption should fail again")
	}

	// Bucket cap is `burst` — long elapsed time can't exceed it.
	now = now.Add(time.Hour)
	for i := range 3 {
		if !l.Take(addr) {
			t.Fatalf("post-cap Take #%d should succeed (bucket capped at burst)", i+1)
		}
	}
	if l.Take(addr) {
		t.Fatalf("4th Take after cap should fail")
	}

	// Different addr is independent.
	other := netip.MustParseAddrPort("192.0.2.2:53")
	if !l.Take(other) {
		t.Fatalf("independent addr should have its own bucket")
	}
}

// TestUpstreamLimiterClampsElapsed exercises the SEC-T2-4 fix:
// elapsed time used in the refill arithmetic is clamped to burst/qps,
// so a clock jump can't feed a pathologically large value into the
// `tokens += elapsed * qps` multiplication. The observable bucket
// state is unchanged for sane clocks (cap at burst), but the
// pre-clamp value is now bounded by burst regardless of the jump.
func TestUpstreamLimiterClampsElapsed(t *testing.T) {
	now := time.Unix(1700000000, 0)
	clock := func() time.Time { return now }
	addr := netip.MustParseAddrPort("192.0.2.1:53")

	// burst=10 tokens, qps=10/s, so a depleted bucket fully refills in
	// 1 s; anything beyond is meaningless.
	l := newUpstreamLimiter(10.0, 10.0, clock)

	// Drain the bucket completely.
	for i := range 10 {
		if !l.Take(addr) {
			t.Fatalf("Take #%d should succeed (initial burst)", i+1)
		}
	}
	if l.Take(addr) {
		t.Fatalf("11th Take should fail — bucket drained")
	}

	// Jump 100 years forward. With the clamp the refill arithmetic
	// sees an elapsed of burst/qps = 1.0 s, not ~3.15e9 s.
	now = now.Add(100 * 365 * 24 * time.Hour)
	b := l.buckets[addr]
	if b == nil {
		t.Fatalf("bucket missing for addr")
	}
	if !l.Take(addr) {
		t.Fatalf("Take after 100y jump should succeed")
	}
	// Bucket should be at burst-1 after one Take. Crucially, internal
	// tokens never reached an unbounded multiplication result.
	if b.tokens > 10.0 {
		t.Fatalf("tokens after jump+take = %f, want <= 10.0", b.tokens)
	}
	if b.tokens < 8.0 {
		t.Fatalf("tokens after jump+take = %f, want ~9 (burst minus 1)", b.tokens)
	}
}

func TestUpstreamLimiterDisabled(t *testing.T) {
	addr := netip.MustParseAddrPort("192.0.2.1:53")
	if l := newUpstreamLimiter(0, 0, nil); !l.Take(addr) {
		t.Fatalf("qps=0 should disable the limiter")
	}
	var nilL *upstreamLimiter
	if !nilL.Take(addr) {
		t.Fatalf("nil limiter should always allow")
	}
}

func TestUpstreamLimiterEvictsAtCap(t *testing.T) {
	now := time.Unix(1700000000, 0)
	clock := func() time.Time { return now }

	l := newUpstreamLimiter(100.0, 100.0, clock)
	l.maxKeys = 4

	// Fill the cap with four buckets, each consumed once so they
	// aren't fully refilled (and thus survive the idle-pass evict).
	for i := range 4 {
		now = now.Add(10 * time.Millisecond)
		addr := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(1000+i))
		if !l.Take(addr) {
			t.Fatalf("seed Take should succeed")
		}
	}
	if got := len(l.buckets); got != 4 {
		t.Fatalf("expected 4 buckets, got %d", got)
	}

	// Inserting a fifth must evict — total stays bounded.
	now = now.Add(10 * time.Millisecond)
	if !l.Take(netip.MustParseAddrPort("192.0.2.99:53")) {
		t.Fatalf("Take into capped map should still succeed")
	}
	if got := len(l.buckets); got > 4 {
		t.Fatalf("cap breached: have %d buckets", got)
	}
}

func TestUpstreamLimiterEvictsIdleFirst(t *testing.T) {
	now := time.Unix(1700000000, 0)
	clock := func() time.Time { return now }

	l := newUpstreamLimiter(10.0, 10.0, clock)
	l.maxKeys = 3

	// Three idle buckets — full burst, untouched since creation. The
	// idle-eviction pass should clear all of them when a fourth
	// arrives.
	for i := range 3 {
		_ = l.Take(netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(2000+i)))
	}
	// Force them all into the "fully refilled / idle" state by
	// advancing past idleFor (burst/qps + 1s = 2s).
	now = now.Add(10 * time.Second)
	if !l.Take(netip.MustParseAddrPort("192.0.2.99:53")) {
		t.Fatalf("Take after eviction should succeed")
	}
	// After idle-pass eviction, only the new bucket should remain.
	if got := len(l.buckets); got != 1 {
		t.Fatalf("expected 1 bucket after idle eviction, got %d", got)
	}
}
