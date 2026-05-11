package recursive_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/recursive"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// stubDialer is a fully programmable Dialer. It dispatches each (server,
// qname, qtype) triple through a user-supplied function.
type stubDialer struct {
	fn func(ctx context.Context, server netip.AddrPort, q wire.Message) (wire.Message, error)
}

func (d stubDialer) Exchange(ctx context.Context, server netip.AddrPort, q wire.Message) (wire.Message, error) {
	return d.fn(ctx, server, q)
}

func mkResp(t *testing.T, q wire.Message, build func(b *wire.MessageBuilder) *wire.MessageBuilder) wire.Message {
	t.Helper()
	question := q.Questions()[0]
	b := wire.NewMessageBuilder().
		ID(q.ID()).
		Response(true).
		Question(question)
	b = build(b)
	resp, err := b.Build()
	require.NoError(t, err)
	return resp
}

// TestCacheGetExpired covers the cache.Get expiry-eviction branch.
func TestCacheGetExpired(t *testing.T) {
	t.Parallel()
	c := recursive.NewMemoryCache()
	name := wire.MustParseName("expired.example.")
	c.Put(name, rrtype.ClassIN, rrtype.A, mustEntry(t, recursive.NewEntryBuilder().
		ExpiresAt(time.Now().Add(-1*time.Second))))
	_, ok := c.Get(name, rrtype.ClassIN, rrtype.A)
	require.False(t, ok, "expired entry should be evicted")

	// Miss.
	_, ok = c.Get(wire.MustParseName("missing.example."), rrtype.ClassIN, rrtype.A)
	require.False(t, ok)
}

// TestMemoryCacheBoundedByMaxSize confirms that filling the cache
// past its configured cap triggers eviction so the entry count stays
// within the per-shard bound. WithMemoryCacheSize is sharded across
// 64 shards (ceil(n/64) per shard), so the actual ceiling is the
// per-shard cap times the shard count.
func TestMemoryCacheBoundedByMaxSize(t *testing.T) {
	t.Parallel()
	const limit = 640
	const numShards = 64
	const perShardCap = (limit + numShards - 1) / numShards
	const ceiling = perShardCap * numShards
	c := recursive.NewMemoryCache(recursive.WithMemoryCacheSize(limit))

	for i := range 4 * limit {
		name := wire.MustParseName(fmt.Sprintf("n%d.example.", i))
		c.Put(name, rrtype.ClassIN, rrtype.A, mustEntry(t, recursive.NewEntryBuilder().
			ExpiresAt(time.Now().Add(time.Duration(i+1)*time.Minute))))
	}
	require.LessOrEqual(t, c.Len(), ceiling,
		"MemoryCache must respect per-shard cap; got %d entries, ceiling %d",
		c.Len(), ceiling)
}

// TestRankServersUntestedFirst covers the rtt=0 ordering branches.
func TestRankServersUntestedFirst(t *testing.T) {
	t.Parallel()
	stats := recursive.NewMemoryStats()
	a := netip.MustParseAddrPort("127.0.0.1:1001")
	b := netip.MustParseAddrPort("127.0.0.1:1002")
	c := netip.MustParseAddrPort("127.0.0.1:1003")

	// a: tested fast, b: untested, c: tested slow with failure.
	stats.Record(a, 5*time.Millisecond, true)
	stats.Record(c, 200*time.Millisecond, true)
	stats.Record(c, 0, false) // bumps streak

	// Trigger ranking by exercising via a Resolver path that uses queryAny.
	// We can't call rankServers directly (unexported), so set up roots and
	// dial logs which order they're attempted in.
	var attempts []netip.AddrPort
	var mu sync.Mutex
	dialer := stubDialer{
		fn: func(_ context.Context, server netip.AddrPort, q wire.Message) (wire.Message, error) {
			mu.Lock()
			attempts = append(attempts, server)
			mu.Unlock()
			// Authoritative empty NXDOMAIN.
			return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
				return b.Authoritative(true).RCODE(wire.RCODENXDomain)
			}), nil
		},
	}
	r := mustRecursive(t,
		recursive.WithRoots(a, b, c),
		recursive.WithDialer(dialer),
		recursive.WithServerStats(stats),
	)
	rctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	_, err := r.ResolveEntry(rctx, wire.MustParseName("nope.example."), rrtype.A)
	require.NoError(t, err)
	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, attempts)
	// First try should be the lowest-streak, lowest-RTT server: b (untested,
	// rtt=0) ties with a but b sorts before c (which has streak=1). Either
	// b or a is acceptable; what matters is c is NOT first.
	require.NotEqual(t, c, attempts[0])
}

// TestCNAMEChainWithMaxDepthZero exercises the early exit when CNAME chase
// is at-or-past the cap on entry.
func TestCNAMEChainWithMaxDepthZero(t *testing.T) {
	t.Parallel()
	dialer := stubDialer{
		fn: func(_ context.Context, _ netip.AddrPort, q wire.Message) (wire.Message, error) {
			return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
				return b.Authoritative(true)
			}), nil
		},
	}
	r := mustRecursive(t,
		recursive.WithRoots(netip.MustParseAddrPort("127.0.0.1:1")),
		recursive.WithDialer(dialer),
		recursive.WithMaxCNAMEDepth(0),
	)
	rctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	_, err := r.ResolveEntry(rctx, wire.MustParseName("a.example."), rrtype.A)
	require.ErrorIs(t, err, recursive.ErrCNAMELoop)
}

// TestUnglueOutOfBailiwickReferral exercises serversFromReferral's recursion
// path: a referral with NS targets that do NOT have glue records.
func TestUnglueOutOfBailiwickReferral(t *testing.T) {
	t.Parallel()
	// We pretend root server lives at 1.0.0.1:53; child lives at 2.0.0.2:53.
	// Step 1: resolver asks root for www.example.com → root returns referral
	//         to ns1.outsider.net (no glue).
	// Step 2: resolver iteratively resolves ns1.outsider.net A starting from
	//         root → root authoritatively answers with 2.0.0.2.
	// Step 3: resolver queries 2.0.0.2:53 for www.example.com → AA answer
	//         192.0.2.55.
	root := netip.MustParseAddrPort("1.0.0.1:53")
	child := netip.MustParseAddrPort("2.0.0.2:53")

	dialer := stubDialer{
		fn: func(_ context.Context, server netip.AddrPort, q wire.Message) (wire.Message, error) {
			question := q.Questions()[0]
			qname := question.Name().String()
			qtype := question.Type()

			switch {
			case server == root && qname == "www.example." && qtype == rrtype.A:
				nsrd, err := rdata.NewNS(wire.MustParseName("ns1.outsider."))
				require.NoError(t, err)
				// referral to ns1.outsider., no glue.
				return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
					ns := wire.NewRecord(wire.MustParseName("example."),
						60*time.Second,
						nsrd)
					return b.Authority(ns)
				}), nil
			case server == root && qname == "ns1.outsider." && qtype == rrtype.A:
				ar, err := rdata.NewA(netip.MustParseAddr("2.0.0.2"))
				require.NoError(t, err)
				return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
					a := wire.NewRecord(wire.MustParseName("ns1.outsider."),
						60*time.Second,
						ar)
					return b.Authoritative(true).Answer(a)
				}), nil
			case server == child && qname == "www.example." && qtype == rrtype.A:
				ar2, err := rdata.NewA(netip.MustParseAddr("192.0.2.55"))
				require.NoError(t, err)
				return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
					a := wire.NewRecord(wire.MustParseName("www.example."),
						60*time.Second,
						ar2)
					return b.Authoritative(true).Answer(a)
				}), nil
			}
			return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
				return b.RCODE(wire.RCODEServFail)
			}), nil
		},
	}

	r := mustRecursive(t,
		recursive.WithRoots(root),
		recursive.WithDialer(dialer),
	)
	rctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	entry, err := r.ResolveEntry(rctx, wire.MustParseName("www.example."), rrtype.A)
	require.NoError(t, err)
	require.Equal(t, 1, len(entry.Answer()))
	require.Equal(t, "192.0.2.55", entry.Answer()[0].RData().(rdata.A).Addr().String())
}

// TestGlueAAAA exercises glueFor's AAAA branch.
func TestGlueAAAA(t *testing.T) {
	t.Parallel()
	root := netip.MustParseAddrPort("1.0.0.1:53")
	child := netip.MustParseAddrPort("[2001:db8::1]:53")

	dialer := stubDialer{
		fn: func(_ context.Context, server netip.AddrPort, q wire.Message) (wire.Message, error) {
			question := q.Questions()[0]
			if server == root {
				aaaa, err := rdata.NewAAAA(netip.MustParseAddr("2001:db8::1"))
				require.NoError(t, err)
				nsrd2, err := rdata.NewNS(wire.MustParseName("ns1.example."))
				require.NoError(t, err)
				return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
					ns := wire.NewRecord(wire.MustParseName("example."),
						60*time.Second,
						nsrd2)
					glue := wire.NewRecord(wire.MustParseName("ns1.example."),
						60*time.Second,
						aaaa)
					return b.Authority(ns).Additional(glue)
				}), nil
			}
			if server == child {
				ar3, err := rdata.NewA(netip.MustParseAddr("192.0.2.7"))
				require.NoError(t, err)
				a := wire.NewRecord(question.Name(), 60*time.Second,
					ar3)
				return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
					return b.Authoritative(true).Answer(a)
				}), nil
			}
			return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
				return b.RCODE(wire.RCODEServFail)
			}), nil
		},
	}
	r := mustRecursive(t,
		recursive.WithRoots(root),
		recursive.WithDialer(dialer),
	)
	rctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	entry, err := r.ResolveEntry(rctx, wire.MustParseName("www.example."), rrtype.A)
	require.NoError(t, err)
	require.Equal(t, 1, len(entry.Answer()))
}

// TestEmptyReferral covers the empty-referral failure path.
func TestEmptyReferral(t *testing.T) {
	t.Parallel()
	root := netip.MustParseAddrPort("1.0.0.1:53")
	dialer := stubDialer{
		fn: func(_ context.Context, _ netip.AddrPort, q wire.Message) (wire.Message, error) {
			// No AA, no answer, no NS → empty referral.
			return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
				return b
			}), nil
		},
	}
	r := mustRecursive(t,
		recursive.WithRoots(root),
		recursive.WithDialer(dialer),
		recursive.WithMaxIterations(2),
	)
	rctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	_, err := r.ResolveEntry(rctx, wire.MustParseName("www.example."), rrtype.A)
	require.ErrorContains(t, err, "empty referral")
}

// TestAllServersLame exercises the SERVFAIL/REFUSED short-circuit when every
// candidate is lame.
func TestAllServersLame(t *testing.T) {
	t.Parallel()
	a := netip.MustParseAddrPort("127.0.0.1:1001")
	b := netip.MustParseAddrPort("127.0.0.1:1002")
	dialer := stubDialer{
		fn: func(_ context.Context, _ netip.AddrPort, q wire.Message) (wire.Message, error) {
			return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
				return b.RCODE(wire.RCODEServFail)
			}), nil
		},
	}
	r := mustRecursive(t,
		recursive.WithRoots(a, b),
		recursive.WithDialer(dialer),
		recursive.WithMaxIterations(5),
	)
	rctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	_, err := r.ResolveEntry(rctx, wire.MustParseName("nope.example."), rrtype.A)
	require.ErrorIs(t, err, recursive.ErrAllServersLame)

	// The wrapper exposes per-server entries: every queried root
	// should appear in Servers() with RCODE=SERVFAIL.
	var ae *recursive.AllServersLameError
	require.ErrorAs(t, err, &ae)
	servers := ae.Servers()
	require.NotEmpty(t, servers)
	seen := make(map[netip.AddrPort]wire.RCODE, len(servers))
	for _, s := range servers {
		require.Equal(t, wire.RCODEServFail, s.RCODE())
		seen[s.Addr()] = s.RCODE()
	}
	require.Contains(t, seen, a)
	require.Contains(t, seen, b)

	// Single-LameServer extraction: errors.As surfaces the first
	// server's entry.
	var ls *recursive.LameServer
	require.ErrorAs(t, err, &ls)
	require.Equal(t, wire.RCODEServFail, ls.RCODE())
}

// TestRefusedTreatedAsLame exercises the REFUSED branch in addition to
// SERVFAIL.
func TestRefusedTreatedAsLame(t *testing.T) {
	t.Parallel()
	// One root that REFUSED, one that returns a clean answer.
	bad := netip.MustParseAddrPort("127.0.0.1:1001")
	good := netip.MustParseAddrPort("127.0.0.1:1002")
	dialer := stubDialer{
		fn: func(_ context.Context, server netip.AddrPort, q wire.Message) (wire.Message, error) {
			if server == bad {
				return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
					return b.RCODE(wire.RCODERefused)
				}), nil
			}
			question := q.Questions()[0]
			ar4, err := rdata.NewA(netip.MustParseAddr("192.0.2.1"))
			require.NoError(t, err)
			ans := wire.NewRecord(question.Name(), 60*time.Second,
				ar4)
			return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
				return b.Authoritative(true).Answer(ans)
			}), nil
		},
	}
	r := mustRecursive(t,
		recursive.WithRoots(bad, good),
		recursive.WithDialer(dialer),
	)
	rctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	entry, err := r.ResolveEntry(rctx, wire.MustParseName("www.example."), rrtype.A)
	require.NoError(t, err)
	require.Equal(t, 1, len(entry.Answer()))
}

// TestQueryAnyAllError exercises the queryAny path where every server errors.
func TestQueryAnyAllError(t *testing.T) {
	t.Parallel()
	dialer := stubDialer{
		fn: func(_ context.Context, _ netip.AddrPort, _ wire.Message) (wire.Message, error) {
			return wire.Message{}, errors.New("synthetic dial failure")
		},
	}
	r := mustRecursive(t,
		recursive.WithRoots(
			netip.MustParseAddrPort("127.0.0.1:1001"),
			netip.MustParseAddrPort("127.0.0.1:1002"),
		),
		recursive.WithDialer(dialer),
	)
	rctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	_, err := r.ResolveEntry(rctx, wire.MustParseName("www.example."), rrtype.A)
	require.ErrorContains(t, err, "synthetic dial failure")
}

// TestQueryAnyContextCancelled exercises queryAny's context-cancelled exit
// after a per-server failure.
func TestQueryAnyContextCancelled(t *testing.T) {
	t.Parallel()
	rctx, cancel := context.WithCancel(t.Context())
	dialer := stubDialer{
		fn: func(_ context.Context, _ netip.AddrPort, _ wire.Message) (wire.Message, error) {
			cancel()
			return wire.Message{}, errors.New("transient")
		},
	}
	r := mustRecursive(t,
		recursive.WithRoots(
			netip.MustParseAddrPort("127.0.0.1:1001"),
			netip.MustParseAddrPort("127.0.0.1:1002"),
		),
		recursive.WithDialer(dialer),
	)
	_, err := r.ResolveEntry(rctx, wire.MustParseName("www.example."), rrtype.A)
	require.ErrorIs(t, err, context.Canceled)
}

// TestServeDNSWithAuthorityAndAdditional exercises the ServeDNS branches that
// copy Authority/Additional records and propagate non-NoError RCODEs and AD.
func TestServeDNSWithAuthorityAndAdditional(t *testing.T) {
	t.Parallel()
	dialer := stubDialer{
		fn: func(_ context.Context, _ netip.AddrPort, q wire.Message) (wire.Message, error) {
			question := q.Questions()[0]
			soa2, err := rdata.NewSOA(
					wire.MustParseName("ns.example."),
					wire.MustParseName("hm.example."),
					1, 60*time.Second, 60*time.Second, 60*time.Second, 30*time.Second)
			require.NoError(t, err)
			soa := wire.NewRecord(wire.MustParseName("example."), 30*time.Second,
				soa2)
			nsrd3, err := rdata.NewNS(wire.MustParseName("ns.example."))
			require.NoError(t, err)
			ns := wire.NewRecord(wire.MustParseName("example."), 60*time.Second,
				nsrd3)
			ar5, err := rdata.NewA(netip.MustParseAddr("192.0.2.1"))
			require.NoError(t, err)
			glue := wire.NewRecord(wire.MustParseName("ns.example."), 60*time.Second,
				ar5)
			_ = question
			return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
				// NXDOMAIN with SOA in authority and a glue in additional, AD set.
				return b.Authoritative(true).
					AuthenticData(true).
					RCODE(wire.RCODENXDomain).
					Authority(soa).
					Authority(ns).
					Additional(glue)
			}), nil
		},
	}
	r := mustRecursive(t,
		recursive.WithRoots(netip.MustParseAddrPort("127.0.0.1:1")),
		recursive.WithDialer(dialer),
	)
	srv, err := acidns.NewUDPServer(netip.MustParseAddrPort("127.0.0.1:0"), r)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)

	require.NoError(t, err)

	q, err := wire.NewMessageBuilder().
		ID(7).
		RecursionDesired(true).
		Question(wire.NewQuestion(wire.MustParseName("nope.example."), rrtype.A)).
		Build()
	require.NoError(t, err)
	ex, err := acidns.NewUDPClient(ctrl.Addr())
	require.NoError(t, err)
	qctx, qcancel := context.WithTimeout(ctx, 2*time.Second)
	defer qcancel()
	resp, err := ex.Exchange(qctx, q)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENXDomain, resp.Flags().RCODE())
	// AD from upstream is intentionally cleared when no Validator is
	// configured: a non-validating recursive resolver propagating AD=1
	// would launder a path-injected forgery's AD bit to its clients.
	require.False(t, resp.Flags().AuthenticData())
	require.GreaterOrEqual(t, len(resp.Authorities()), 1)
	require.GreaterOrEqual(t, len(resp.Additionals()), 1)
}

// TestServeDNSBogusServfailWithEDE exercises the bogus → SERVFAIL+EDE6 path
// in ServeDNS.
func TestServeDNSBogusServfailWithEDE(t *testing.T) {
	t.Parallel()
	dialer := stubDialer{
		fn: func(_ context.Context, _ netip.AddrPort, q wire.Message) (wire.Message, error) {
			question := q.Questions()[0]
			ar6, err := rdata.NewA(netip.MustParseAddr("192.0.2.1"))
			require.NoError(t, err)
			a := wire.NewRecord(question.Name(), 60*time.Second,
				ar6)
			return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
				return b.Authoritative(true).Answer(a)
			}), nil
		},
	}
	r := mustRecursive(t,
		recursive.WithRoots(netip.MustParseAddrPort("127.0.0.1:1")),
		recursive.WithDialer(dialer),
		recursive.WithValidator(validatorStub{status: recursive.StatusBogus}),
	)
	srv, err := acidns.NewUDPServer(netip.MustParseAddrPort("127.0.0.1:0"), r)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)

	require.NoError(t, err)

	q, err := wire.NewMessageBuilder().
		ID(8).
		RecursionDesired(true).
		Question(wire.NewQuestion(wire.MustParseName("www.example."), rrtype.A)).
		Build()
	require.NoError(t, err)
	ex, err := acidns.NewUDPClient(ctrl.Addr())
	require.NoError(t, err)
	qctx, qcancel := context.WithTimeout(ctx, 2*time.Second)
	defer qcancel()
	resp, err := ex.Exchange(qctx, q)
	require.NoError(t, err)
	require.Equal(t, wire.RCODEServFail, resp.Flags().RCODE())
}

// TestValidatorErrorPropagated covers Validator.Resolve returning a non-nil
// error.
func TestValidatorErrorPropagated(t *testing.T) {
	t.Parallel()
	dialer := stubDialer{
		fn: func(_ context.Context, _ netip.AddrPort, q wire.Message) (wire.Message, error) {
			question := q.Questions()[0]
			ar7, err := rdata.NewA(netip.MustParseAddr("192.0.2.1"))
			require.NoError(t, err)
			a := wire.NewRecord(question.Name(), 60*time.Second,
				ar7)
			return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
				return b.Authoritative(true).Answer(a)
			}), nil
		},
	}
	myErr := errors.New("validator boom")
	r := mustRecursive(t,
		recursive.WithRoots(netip.MustParseAddrPort("127.0.0.1:1")),
		recursive.WithDialer(dialer),
		recursive.WithValidator(validatorStub{err: myErr}),
	)
	rctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	_, err := r.ResolveEntry(rctx, wire.MustParseName("www.example."), rrtype.A)
	require.ErrorIs(t, err, myErr)
}

// TestTCPFallbackOnTruncated drives the defaultDialer's TC=1 → TCP fallback
// path. We bind a UDP server that always sets TC, and a TCP server (same
// port) that returns a normal answer — defaultDialer should re-issue over
// TCP.
func TestTCPFallbackOnTruncated(t *testing.T) {
	t.Parallel()
	udpHandler := acidns.HandlerFunc(func(_ context.Context, w acidns.ResponseWriter, q wire.Message) {
		question := q.Questions()[0]
		resp, _ := wire.NewMessageBuilder().
			ID(q.ID()).
			Response(true).
			Authoritative(true).
			Truncated(true).
			Question(question).
			Build()
		_ = w.WriteMsg(resp)
	})
	tcpHandler := acidns.HandlerFunc(func(_ context.Context, w acidns.ResponseWriter, q wire.Message) {
		question := q.Questions()[0]
		ar8, err := rdata.NewA(netip.MustParseAddr("192.0.2.99"))
		require.NoError(t, err)
		a := wire.NewRecord(question.Name(), 60*time.Second,
			ar8)
		resp, _ := wire.NewMessageBuilder().
			ID(q.ID()).
			Response(true).
			Authoritative(true).
			Question(question).
			Answer(a).
			Build()
		_ = w.WriteMsg(resp)
	})

	udpSrv, err := acidns.NewUDPServer(netip.MustParseAddrPort("127.0.0.1:0"), udpHandler)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	udpCtrl, err := udpSrv.Run(ctx)
	require.NoError(t, err)
	udpAddr := udpCtrl.Addr()
	// Bind TCP to the same UDP port (typical for DNS auth servers). Try the
	// already-known port; if another process steals it between calls we're
	// fine because the test will fail loudly.
	tcpSrv, err := acidns.NewTCPServer(udpAddr, tcpHandler)
	require.NoError(t, err)
	_, err = tcpSrv.Run(ctx)
	require.NoError(t, err)

	d := recursive.DefaultDialer()
	q, err := wire.NewMessageBuilder().
		ID(0xdead).
		Question(wire.NewQuestion(wire.MustParseName("www.example."), rrtype.A)).
		Build()
	require.NoError(t, err)
	rctx, rcancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer rcancel()
	resp, err := d.Exchange(rctx, udpAddr, q)
	require.NoError(t, err)
	// On the TCP retry we expect a non-truncated answer with the A record.
	require.False(t, resp.Flags().Truncated())
	require.Equal(t, 1, len(resp.Answers()))
}

// TestTCPFallbackTCPDialFails covers the path where TC=1 triggers a TCP
// retry but no TCP listener exists. The dialer must surface the failure
// rather than return the truncated UDP answer — a network adversary
// that can drop 53/tcp would otherwise force the resolver to operate
// on partial data (DNSSEC RRSIGs typically don't fit in 512 bytes).
func TestTCPFallbackTCPDialFails(t *testing.T) {
	t.Parallel()
	udpHandler := acidns.HandlerFunc(func(_ context.Context, w acidns.ResponseWriter, q wire.Message) {
		question := q.Questions()[0]
		resp, _ := wire.NewMessageBuilder().
			ID(q.ID()).
			Response(true).
			Authoritative(true).
			Truncated(true).
			Question(question).
			Build()
		_ = w.WriteMsg(resp)
	})
	udpSrv, err := acidns.NewUDPServer(netip.MustParseAddrPort("127.0.0.1:0"), udpHandler)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	udpCtrl, err := udpSrv.Run(ctx)

	require.NoError(t, err)

	d := recursive.DefaultDialer()
	q, err := wire.NewMessageBuilder().
		ID(0xbeef).
		Question(wire.NewQuestion(wire.MustParseName("www.example."), rrtype.A)).
		Build()
	require.NoError(t, err)
	rctx, rcancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer rcancel()
	_, err = d.Exchange(rctx, udpCtrl.Addr(), q)
	require.ErrorIs(t, err, recursive.ErrTruncatedAfterTCPFail)
}

// TestNonAAResponseTreatedAsAuthoritative exercises the path where the
// resolved server doesn't set AA but produces matching answer records.
func TestNonAAResponseTreatedAsAuthoritative(t *testing.T) {
	t.Parallel()
	dialer := stubDialer{
		fn: func(_ context.Context, _ netip.AddrPort, q wire.Message) (wire.Message, error) {
			question := q.Questions()[0]
			ar9, err := rdata.NewA(netip.MustParseAddr("192.0.2.50"))
			require.NoError(t, err)
			a := wire.NewRecord(question.Name(), 60*time.Second,
				ar9)
			return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
				return b.Answer(a) // AA=false
			}), nil
		},
	}
	r := mustRecursive(t,
		recursive.WithRoots(netip.MustParseAddrPort("127.0.0.1:1")),
		recursive.WithDialer(dialer),
	)
	rctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	entry, err := r.ResolveEntry(rctx, wire.MustParseName("www.example."), rrtype.A)
	require.NoError(t, err)
	require.Equal(t, 1, len(entry.Answer()))
	require.False(t, entry.AA())
}

// TestResolveCNAMEDirectly exercises the resolveDepthFollow path where the
// caller asks for the CNAME type directly — the loop must return the answer
// without chasing.
func TestResolveCNAMEDirectly(t *testing.T) {
	t.Parallel()
	dialer := stubDialer{
		fn: func(_ context.Context, _ netip.AddrPort, q wire.Message) (wire.Message, error) {
			question := q.Questions()[0]
			cn, err := rdata.NewCNAME(wire.MustParseName("alias.example."))
			require.NoError(t, err)
			cname := wire.NewRecord(question.Name(), 60*time.Second,
				cn)
			return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
				return b.Authoritative(true).Answer(cname)
			}), nil
		},
	}
	r := mustRecursive(t,
		recursive.WithRoots(netip.MustParseAddrPort("127.0.0.1:1")),
		recursive.WithDialer(dialer),
	)
	rctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	entry, err := r.ResolveEntry(rctx, wire.MustParseName("www.example."), rrtype.CNAME)
	require.NoError(t, err)
	require.Equal(t, 1, len(entry.Answer()))
	require.Equal(t, rrtype.CNAME, entry.Answer()[0].Type())
}

// TestNegativeCacheTTLTakesRecordTTLWhenSmaller exercises the
// negativeCacheTTL branch where the SOA record's own TTL is smaller than
// the SOA MINIMUM field.
func TestNegativeCacheTTLTakesRecordTTLWhenSmaller(t *testing.T) {
	t.Parallel()
	dialer := stubDialer{
		fn: func(_ context.Context, _ netip.AddrPort, q wire.Message) (wire.Message, error) {
			soa3, err := rdata.NewSOA(
					wire.MustParseName("ns.example."),
					wire.MustParseName("hm.example."),
					1, 60*time.Second, 60*time.Second, 60*time.Second, 30*time.Second)
			require.NoError(t, err)
			// Record TTL = 5s, SOA MINIMUM = 30s → cache uses the smaller TTL.
			soa := wire.NewRecord(wire.MustParseName("example."), 5*time.Second,
				soa3)
			return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
				return b.Authoritative(true).RCODE(wire.RCODENXDomain).Authority(soa)
			}), nil
		},
	}
	r := mustRecursive(t,
		recursive.WithRoots(netip.MustParseAddrPort("127.0.0.1:1")),
		recursive.WithDialer(dialer),
	)
	rctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	entry, err := r.ResolveEntry(rctx, wire.MustParseName("nope.example."), rrtype.A)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENXDomain, entry.RCODE())
	// Expires within ~6s (record TTL 5s).
	require.LessOrEqual(t, time.Until(entry.ExpiresAt()), 7*time.Second)
}

// TestHasAnswerForCNAMEAtOwner exercises hasAnswerFor's CNAME branch when
// the answer holds a CNAME at the queried name but the response is not AA.
func TestHasAnswerForCNAMEAtOwner(t *testing.T) {
	t.Parallel()
	target := wire.MustParseName("alias.example.")
	dialer := stubDialer{
		fn: func(_ context.Context, _ netip.AddrPort, q wire.Message) (wire.Message, error) {
			question := q.Questions()[0]
			if question.Name().Equal(wire.MustParseName("www.example.")) {
				cn2, err := rdata.NewCNAME(target)
				require.NoError(t, err)
				cname := wire.NewRecord(question.Name(), 60*time.Second,
					cn2)
				// AA=false to drive the hasAnswerFor branch.
				return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
					return b.Answer(cname)
				}), nil
			}
			// Resolve the alias to an A.
			ar10, err := rdata.NewA(netip.MustParseAddr("192.0.2.77"))
			require.NoError(t, err)
			a := wire.NewRecord(question.Name(), 60*time.Second,
				ar10)
			return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
				return b.Authoritative(true).Answer(a)
			}), nil
		},
	}
	r := mustRecursive(t,
		recursive.WithRoots(netip.MustParseAddrPort("127.0.0.1:1")),
		recursive.WithDialer(dialer),
	)
	rctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	entry, err := r.ResolveEntry(rctx, wire.MustParseName("www.example."), rrtype.A)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(entry.Answer()), 1)
}

// TestIterationLimitReached covers the path where successive non-terminal
// referrals exhaust maxIterations.
func TestIterationLimitReached(t *testing.T) {
	t.Parallel()
	var count atomic.Int32
	root := netip.MustParseAddrPort("127.0.0.1:1")
	dialer := stubDialer{
		fn: func(_ context.Context, _ netip.AddrPort, q wire.Message) (wire.Message, error) {
			count.Add(1)
			// Each response is a referral to the next "level"; we keep
			// returning glue at 127.0.0.1:1 (same root) so we just spin.
			nsrd4, err := rdata.NewNS(wire.MustParseName("ns.example."))
			require.NoError(t, err)
			ns := wire.NewRecord(wire.MustParseName("example."),
				60*time.Second,
				nsrd4)
			ar11, err := rdata.NewA(netip.MustParseAddr("127.0.0.1"))
			require.NoError(t, err)
			glue := wire.NewRecord(wire.MustParseName("ns.example."),
				60*time.Second,
				ar11)
			return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
				return b.Authority(ns).Additional(glue)
			}), nil
		},
	}
	r := mustRecursive(t,
		recursive.WithRoots(root),
		recursive.WithDialer(dialer),
		recursive.WithMaxIterations(3),
	)
	rctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	_, err := r.ResolveEntry(rctx, wire.MustParseName("www.example."), rrtype.A)
	require.ErrorIs(t, err, recursive.ErrIterationLimit)
}

// TestResolveSingleflightCoalesces verifies that concurrent goroutines
// missing the cache for the same (qname, qtype) produce a single
// upstream exchange. RFC 5452 §6: each independent transmission is a
// fresh forgery window — a thundering herd quadratically multiplies an
// off-path attacker's chances. With singleflight in place, N callers
// share one window.
func TestResolveSingleflightCoalesces(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	var calls atomic.Int64
	dialer := stubDialer{
		fn: func(_ context.Context, _ netip.AddrPort, q wire.Message) (wire.Message, error) {
			calls.Add(1)
			<-release // hold all callers until they have all joined
			question := q.Questions()[0]
			ar12, err := rdata.NewA(netip.MustParseAddr("203.0.113.99"))
			require.NoError(t, err)
			a := wire.NewRecord(question.Name(), 60*time.Second,
				ar12)
			return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
				return b.Authoritative(true).Answer(a)
			}), nil
		},
	}
	r := mustRecursive(t,
		recursive.WithRoots(netip.MustParseAddrPort("127.0.0.1:1")),
		recursive.WithDialer(dialer),
		// Disable qname-minimisation so the test counts upstream calls
		// per Resolve, not per minimisation hop. This test is about
		// singleflight; qmin's per-step queries are a separate concern.
		recursive.WithQNameMinimisation(false),
	)

	const callers = 16
	var wg sync.WaitGroup
	results := make([]error, callers)
	for i := range callers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			_, err := r.ResolveEntry(rctx, wire.MustParseName("herd.example."), rrtype.A)
			results[i] = err
		}(i)
	}

	// Give the callers a chance to all enter resolveDepth and join the
	// in-flight call before we release the upstream response.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	for i, err := range results {
		require.NoError(t, err, "caller %d", i)
	}
	require.Equal(t, int64(1), calls.Load(),
		"singleflight must collapse %d concurrent identical queries to one upstream exchange", callers)
}

// TestResolveSingleflightLeaderCancelDoesNotOrphanFollowers verifies
// that when the singleflight leader's context is cancelled mid-flight,
// followers waiting on the same in-flight call still observe the
// upstream's successful answer rather than the leader's
// context.Canceled. Without context detachment (see
// recursive.startResolveDepth), a cancelled leader would tear down the
// shared work and surface ctx.Err() to every follower — an RFC 5452 §6
// amplification vector, since every orphaned follower would have to
// re-issue the full iterative walk and open a fresh spoofing window.
func TestResolveSingleflightLeaderCancelDoesNotOrphanFollowers(t *testing.T) {
	t.Parallel()
	// release gates the upstream response; close it to let the dialer
	// return. The leader's ctx is cancelled before release is closed,
	// so the in-flight goroutine is actively running when the leader
	// abandons it.
	release := make(chan struct{})
	leaderJoined := make(chan struct{})
	followerJoined := make(chan struct{})
	var calls atomic.Int64
	dialer := stubDialer{
		fn: func(ctx context.Context, _ netip.AddrPort, q wire.Message) (wire.Message, error) {
			calls.Add(1)
			select {
			case <-release:
			case <-ctx.Done():
				return wire.Message{}, ctx.Err()
			}
			question := q.Questions()[0]
			ar, err := rdata.NewA(netip.MustParseAddr("203.0.113.7"))
			require.NoError(t, err)
			a := wire.NewRecord(question.Name(), 60*time.Second, ar)
			return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
				return b.Authoritative(true).Answer(a)
			}), nil
		},
	}
	r := mustRecursive(t,
		recursive.WithRoots(netip.MustParseAddrPort("127.0.0.1:1")),
		recursive.WithDialer(dialer),
		// Disable qname-minimisation: this test counts on a single
		// (qname, qtype) singleflight entry, not per-step queries.
		recursive.WithQNameMinimisation(false),
	)

	name := wire.MustParseName("orphan.example.")

	leaderCtx, cancelLeader := context.WithCancel(t.Context())
	leaderErrCh := make(chan error, 1)
	go func() {
		close(leaderJoined)
		_, err := r.ResolveEntry(leaderCtx, name, rrtype.A)
		leaderErrCh <- err
	}()

	// Wait until the leader is in-flight, then start the follower.
	<-leaderJoined
	// Give the leader time to enter the dialer (the dialer's first
	// call increments calls.Load to 1 before blocking on release).
	require.Eventually(t, func() bool { return calls.Load() == 1 },
		2*time.Second, time.Millisecond, "leader must reach the dialer")

	followerCtx, cancelFollower := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancelFollower()
	followerResultCh := make(chan struct {
		entry recursive.Entry
		err   error
	}, 1)
	go func() {
		close(followerJoined)
		entry, err := r.ResolveEntry(followerCtx, name, rrtype.A)
		followerResultCh <- struct {
			entry recursive.Entry
			err   error
		}{entry, err}
	}()
	<-followerJoined
	// Give the follower a moment to join the in-flight entry.
	time.Sleep(50 * time.Millisecond)

	// Cancel the leader while the upstream is still blocked. The
	// follower must still be able to complete.
	cancelLeader()

	// The leader sees context.Canceled (its own ctx fired).
	select {
	case err := <-leaderErrCh:
		require.ErrorIs(t, err, context.Canceled, "leader must observe its own cancel")
	case <-time.After(2 * time.Second):
		t.Fatal("leader did not return after cancellation")
	}

	// The detached in-flight goroutine is still running; release it
	// so the follower can complete.
	close(release)

	select {
	case got := <-followerResultCh:
		require.NoError(t, got.err,
			"follower must NOT inherit the leader's cancellation")
		// Sanity: the answer is the upstream's, not a stale/empty entry.
		require.NotEmpty(t, got.entry.Answer(),
			"follower must receive the iterative-walk answer")
	case <-time.After(3 * time.Second):
		t.Fatal("follower did not complete after upstream release")
	}

	// Exactly one upstream call: singleflight coalesced the two
	// resolutions even though the leader cancelled mid-flight.
	require.Equal(t, int64(1), calls.Load(),
		"singleflight must hold across leader cancellation; got %d upstream calls", calls.Load())
}
