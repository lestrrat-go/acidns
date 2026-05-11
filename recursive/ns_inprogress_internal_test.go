package recursive

import (
	"testing"

	"github.com/lestrrat-go/acidns/wire"
)

// TestNSInProgressUnmarkOnPanic exercises the defer-pattern
// established in resolveUngluedNS: after markNSInProgress claims
// an NS, a panic in the body of the same function (between mark
// and any explicit unmark call site) must NOT leak the claim.
//
// The fix replaces the old explicit `unmarkNSInProgress(nsKey)`
// at the bottom of the loop body with a `defer unmarkNSInProgress`
// immediately after a successful mark, inside a helper function so
// the deferred call fires per-iteration. We assert that property
// here by simulating the same pattern with an injected panic.
func TestNSInProgressUnmarkOnPanic(t *testing.T) {
	r := &Recursive{nsInProgress: make(map[string]struct{})}

	ns := wire.MustParseName("ns.example.")
	nsKey := nameKey(ns)

	func() {
		defer func() {
			if rec := recover(); rec == nil {
				t.Fatalf("expected panic to propagate to recover boundary")
			}
		}()
		if !r.markNSInProgress(nsKey) {
			t.Fatalf("markNSInProgress should succeed on a fresh resolver")
		}
		defer r.unmarkNSInProgress(nsKey)
		// Simulate a panic somewhere between mark and the eventual
		// unmark — exactly the scenario the defer protects against.
		panic("simulated failure during NS chase")
	}()

	r.nsInProgressMu.Lock()
	_, stillMarked := r.nsInProgress[nsKey]
	r.nsInProgressMu.Unlock()
	if stillMarked {
		t.Fatalf("nsInProgress[%q] leaked after panic — deferred unmark did not run", nsKey)
	}

	// Sanity: a fresh mark must succeed (i.e. the map is genuinely
	// clean, not merely missing this one key by accident).
	if !r.markNSInProgress(nsKey) {
		t.Fatalf("post-cleanup markNSInProgress should succeed; key is still claimed")
	}
	r.unmarkNSInProgress(nsKey)
}
