package recursive_test

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/recursive"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// TestNSInProgressSharedAcrossResolves drives an adversarial NS
// graph from many concurrent goroutines. Without the shared cycle
// set, each goroutine independently chases the graph until its own
// per-Resolve cycle detector fires; with the shared set, only one
// goroutine actually walks the trap and the rest skip immediately.
//
// We assert the trap-NS resolution count stays small (independent
// of goroutine count) — proving the shared guard prevents
// amplification.
func TestNSInProgressSharedAcrossResolves(t *testing.T) {
	t.Parallel()

	var trapHits atomic.Int32
	dialer := stubDialer{
		fn: func(_ context.Context, _ netip.AddrPort, q wire.Message) (wire.Message, error) {
			question := q.Questions()[0]
			qname := question.Name()
			// Root referrals point any qname under "trap.example."
			// at the malicious zone "ns.trap.example." whose NS is
			// itself out-of-bailiwick — chasing it requires
			// re-resolving ns.trap.example which then needs ns of
			// its own, a self-reference.
			//
			// To recognise the in-progress NS chase, count every
			// time we are asked to resolve the trap NS itself.
			if qname.Equal(wire.MustParseName("ns.trap.example.")) {
				trapHits.Add(1)
				// Stall briefly so the concurrent goroutines
				// genuinely overlap on the trap.
				select {
				case <-time.After(50 * time.Millisecond):
				case <-time.After(time.Second): // backstop
				}
				return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
					return b.Authoritative(true) // empty answer; resolution fails
				}), nil
			}
			// All other qnames receive a referral to the trap zone
			// with an out-of-bailiwick NS that requires recursing.
			return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
				ns := wire.NewRecord(wire.MustParseName("trap.example."),
					60*time.Second,
					rdata.MustNewNS(wire.MustParseName("ns.trap.example.")))
				return b.Authority(ns)
			}), nil
		},
	}

	r := mustRecursive(t,
		recursive.WithRoots(netip.MustParseAddrPort("127.0.0.1:1")),
		recursive.WithDialer(dialer),
		recursive.WithMaxIterations(4),
		recursive.WithResolveBudget(2*time.Second),
	)

	// Fan out: 10 concurrent Resolves of distinct qnames under the
	// trap zone. Distinct qnames so the top-level singleflight
	// doesn't coalesce them — only the NS-chase guard can prevent
	// amplification.
	const n = 10
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			qname := wire.MustParseName(
				wire.MustParseName("a" +
					string(rune('0'+(i%10))) + ".trap.example.").String())
			_, _ = r.Resolve(ctx, qname, rrtype.A)
		}(i)
	}
	wg.Wait()

	// Without the shared guard, every concurrent Resolve would
	// independently call resolveDepth(ns.trap.example, A). With it,
	// only one goroutine wins the markNSInProgress race per
	// concurrent burst. The exact count varies with timing, but it
	// must be much less than n.
	hits := trapHits.Load()
	require.Less(t, int(hits), n,
		"shared cycle set must coalesce concurrent NS chases (got %d hits across %d Resolves)", hits, n)
}
