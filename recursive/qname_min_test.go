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
				ar, err := rdata.NewA(netip.MustParseAddr("192.0.2.10"))
				require.NoError(t, err)
				nsrd, err := rdata.NewNS(wire.MustParseName("ns.com."))
				require.NoError(t, err)
				// Root referral to com.
				return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
					ns := wire.NewRecord(wire.MustParseName("com."), time.Hour,
						nsrd)
					glue := wire.NewRecord(wire.MustParseName("ns.com."), time.Hour,
						ar)
					return b.Authority(ns).Additional(glue)
				}), nil
			case "example.com.":
				ar2, err := rdata.NewA(netip.MustParseAddr("192.0.2.20"))
				require.NoError(t, err)
				nsrd2, err := rdata.NewNS(wire.MustParseName("ns.example.com."))
				require.NoError(t, err)
				// com. referral to example.com.
				return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
					ns := wire.NewRecord(wire.MustParseName("example.com."), time.Hour,
						nsrd2)
					glue := wire.NewRecord(wire.MustParseName("ns.example.com."), time.Hour,
						ar2)
					return b.Authority(ns).Additional(glue)
				}), nil
			case "www.example.com.":
				ar3, err := rdata.NewA(netip.MustParseAddr("203.0.113.5"))
				require.NoError(t, err)
				// example.com. authoritative answer.
				return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
					a := wire.NewRecord(qname, time.Minute,
						ar3)
					return b.Authoritative(true).Answer(a)
				}), nil
			}
			// Unhandled name — empty NoError to force fallback.
			return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
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
	entry, err := r.ResolveEntry(ctx, wire.MustParseName("www.example.com."), rrtype.A)
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
				ar4, err := rdata.NewA(netip.MustParseAddr("192.0.2.10"))
				require.NoError(t, err)
				nsrd3, err := rdata.NewNS(wire.MustParseName("ns.com."))
				require.NoError(t, err)
				return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
					ns := wire.NewRecord(wire.MustParseName("com."), time.Hour,
						nsrd3)
					glue := wire.NewRecord(wire.MustParseName("ns.com."), time.Hour,
						ar4)
					return b.Authority(ns).Additional(glue)
				}), nil
			case 2:
				ar5, err := rdata.NewA(netip.MustParseAddr("192.0.2.20"))
				require.NoError(t, err)
				nsrd4, err := rdata.NewNS(wire.MustParseName("ns.example.com."))
				require.NoError(t, err)
				return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
					ns := wire.NewRecord(wire.MustParseName("example.com."), time.Hour,
						nsrd4)
					glue := wire.NewRecord(wire.MustParseName("ns.example.com."), time.Hour,
						ar5)
					return b.Authority(ns).Additional(glue)
				}), nil
			default:
				ar6, err := rdata.NewA(netip.MustParseAddr("203.0.113.5"))
				require.NoError(t, err)
				return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
					a := wire.NewRecord(question.Name(), time.Minute,
						ar6)
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
	_, err := r.ResolveEntry(ctx, wire.MustParseName("www.example.com."), rrtype.A)
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
				ar7, err := rdata.NewA(netip.MustParseAddr("203.0.113.7"))
				require.NoError(t, err)
				return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
					a := wire.NewRecord(qname, time.Minute,
						ar7)
					return b.Authoritative(true).Answer(a)
				}), nil
			}
			// Any intermediate query: misimplemented ENT — return NXDOMAIN
			// from an authoritative source.
			return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
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
	_, err := r.ResolveEntry(ctx, wire.MustParseName("www.example.com."), rrtype.A)
	require.NoError(t, err, "resolver must fall back to full qname after intermediate NXDOMAIN")
	require.True(t, seenFullTarget, "fallback path must reach the full target qname")
}
