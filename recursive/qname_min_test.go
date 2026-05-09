package recursive_test

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/recursive"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// TestQNameMinimisationSendsMinimisedQueries traces the qnames the
// resolver actually sends upstream during a multi-label resolution.
// With qmin enabled (default), each iteration step should expose
// only one more label than the closest known zone — root sees the
// TLD, TLD sees the second-level, etc.
func TestQNameMinimisationSendsMinimisedQueries(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var sentQNames []string

	dialer := stubDialer{
		fn: func(_ context.Context, _ netip.AddrPort, q wire.Message) (wire.Message, error) {
			question := q.Questions()[0]
			mu.Lock()
			sentQNames = append(sentQNames, question.Name().String())
			mu.Unlock()

			qname := question.Name()
			switch qname.String() {
			case "com.":
				// Root referral to com.
				return mkResp(t, q, func(b *wire.Builder) *wire.Builder {
					ns := wire.NewRecord(wire.MustParseName("com."), time.Hour,
						rdata.MustNewNS(wire.MustParseName("ns.com.")))
					glue := wire.NewRecord(wire.MustParseName("ns.com."), time.Hour,
						rdata.MustNewA(netip.MustParseAddr("192.0.2.10")))
					return b.Authority(ns).Additional(glue)
				}), nil
			case "example.com.":
				// com. referral to example.com.
				return mkResp(t, q, func(b *wire.Builder) *wire.Builder {
					ns := wire.NewRecord(wire.MustParseName("example.com."), time.Hour,
						rdata.MustNewNS(wire.MustParseName("ns.example.com.")))
					glue := wire.NewRecord(wire.MustParseName("ns.example.com."), time.Hour,
						rdata.MustNewA(netip.MustParseAddr("192.0.2.20")))
					return b.Authority(ns).Additional(glue)
				}), nil
			case "www.example.com.":
				// example.com. authoritative answer.
				return mkResp(t, q, func(b *wire.Builder) *wire.Builder {
					a := wire.NewRecord(qname, time.Minute,
						rdata.MustNewA(netip.MustParseAddr("203.0.113.5")))
					return b.Authoritative(true).Answer(a)
				}), nil
			}
			// Unhandled name — empty NoError to force fallback.
			return mkResp(t, q, func(b *wire.Builder) *wire.Builder {
				return b.Authoritative(true)
			}), nil
		},
	}

	r := mustRecursive(t,
		recursive.WithRoots(netip.MustParseAddrPort("127.0.0.1:1")),
		recursive.WithDialer(dialer),
	)

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	entry, err := r.Resolve(ctx, wire.MustParseName("www.example.com."), rrtype.A)
	require.NoError(t, err)
	require.Equal(t, 1, len(entry.Answer()))

	mu.Lock()
	defer mu.Unlock()
	// Expected sequence under qmin: com. (root sees TLD only),
	// example.com. (com. sees second-level only), www.example.com.
	// (example.com. sees full target).
	require.Equal(t, []string{"com.", "example.com.", "www.example.com."}, sentQNames,
		"qname-minimised resolver should send progressively-disclosed qnames")
}

// TestQNameMinimisationDisabled verifies WithQNameMinimisation(false)
// reverts to straight-walk: every iteration sends the full target.
func TestQNameMinimisationDisabled(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var sentQNames []string

	dialer := stubDialer{
		fn: func(_ context.Context, _ netip.AddrPort, q wire.Message) (wire.Message, error) {
			question := q.Questions()[0]
			mu.Lock()
			sentQNames = append(sentQNames, question.Name().String())
			mu.Unlock()
			// The full qname goes to every server. Root referrals to
			// com., com. referrals to example.com., final answer.
			switch len(sentQNames) {
			case 1:
				return mkResp(t, q, func(b *wire.Builder) *wire.Builder {
					ns := wire.NewRecord(wire.MustParseName("com."), time.Hour,
						rdata.MustNewNS(wire.MustParseName("ns.com.")))
					glue := wire.NewRecord(wire.MustParseName("ns.com."), time.Hour,
						rdata.MustNewA(netip.MustParseAddr("192.0.2.10")))
					return b.Authority(ns).Additional(glue)
				}), nil
			case 2:
				return mkResp(t, q, func(b *wire.Builder) *wire.Builder {
					ns := wire.NewRecord(wire.MustParseName("example.com."), time.Hour,
						rdata.MustNewNS(wire.MustParseName("ns.example.com.")))
					glue := wire.NewRecord(wire.MustParseName("ns.example.com."), time.Hour,
						rdata.MustNewA(netip.MustParseAddr("192.0.2.20")))
					return b.Authority(ns).Additional(glue)
				}), nil
			default:
				return mkResp(t, q, func(b *wire.Builder) *wire.Builder {
					a := wire.NewRecord(question.Name(), time.Minute,
						rdata.MustNewA(netip.MustParseAddr("203.0.113.5")))
					return b.Authoritative(true).Answer(a)
				}), nil
			}
		},
	}

	r := mustRecursive(t,
		recursive.WithRoots(netip.MustParseAddrPort("127.0.0.1:1")),
		recursive.WithDialer(dialer),
		recursive.WithQNameMinimisation(false),
	)

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	_, err := r.Resolve(ctx, wire.MustParseName("www.example.com."), rrtype.A)
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	for i, n := range sentQNames {
		require.Equal(t, "www.example.com.", n,
			"straight-walk: every step sends the full target qname (step %d sent %q)", i, n)
	}
}

// TestQNameMinimisationFallsBackOnNXDOMAIN drives an upstream that
// (incorrectly) returns NXDOMAIN at an intermediate name. The
// resolver should fall back to the full target qname per RFC 9156
// §2.4.2 and complete resolution.
func TestQNameMinimisationFallsBackOnNXDOMAIN(t *testing.T) {
	t.Parallel()

	var seenFullTarget bool
	dialer := stubDialer{
		fn: func(_ context.Context, _ netip.AddrPort, q wire.Message) (wire.Message, error) {
			qname := q.Questions()[0].Name()
			if qname.String() == "www.example.com." {
				seenFullTarget = true
				return mkResp(t, q, func(b *wire.Builder) *wire.Builder {
					a := wire.NewRecord(qname, time.Minute,
						rdata.MustNewA(netip.MustParseAddr("203.0.113.7")))
					return b.Authoritative(true).Answer(a)
				}), nil
			}
			// Any intermediate query: misimplemented ENT — return NXDOMAIN
			// from an authoritative source.
			return mkResp(t, q, func(b *wire.Builder) *wire.Builder {
				return b.Authoritative(true).RCODE(wire.RCODENXDomain)
			}), nil
		},
	}

	r := mustRecursive(t,
		recursive.WithRoots(netip.MustParseAddrPort("127.0.0.1:1")),
		recursive.WithDialer(dialer),
	)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	_, err := r.Resolve(ctx, wire.MustParseName("www.example.com."), rrtype.A)
	require.NoError(t, err, "resolver must fall back to full qname after intermediate NXDOMAIN")
	require.True(t, seenFullTarget, "fallback path must reach the full target qname")
}
