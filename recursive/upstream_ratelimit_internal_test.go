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
	for i := 0; i < 3; i++ {
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
	for i := 0; i < 3; i++ {
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
