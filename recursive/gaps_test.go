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

func mkResp(t *testing.T, q wire.Message, build func(b *wire.Builder) *wire.Builder) wire.Message {
	t.Helper()
	question := q.Questions()[0]
	b := wire.NewBuilder().
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
			return mkResp(t, q, func(b *wire.Builder) *wire.Builder {
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
	_, err := r.Resolve(rctx, wire.MustParseName("nope.example."), rrtype.A)
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
			return mkResp(t, q, func(b *wire.Builder) *wire.Builder {
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
	_, err := r.Resolve(rctx, wire.MustParseName("a.example."), rrtype.A)
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
				// referral to ns1.outsider., no glue.
				return mkResp(t, q, func(b *wire.Builder) *wire.Builder {
					ns := wire.NewRecord(wire.MustParseName("example."),
						60*time.Second,
						rdata.NewNS(wire.MustParseName("ns1.outsider.")))
					return b.Authority(ns)
				}), nil
			case server == root && qname == "ns1.outsider." && qtype == rrtype.A:
				return mkResp(t, q, func(b *wire.Builder) *wire.Builder {
					a := wire.NewRecord(wire.MustParseName("ns1.outsider."),
						60*time.Second,
						rdata.NewA(netip.MustParseAddr("2.0.0.2")))
					return b.Authoritative(true).Answer(a)
				}), nil
			case server == child && qname == "www.example." && qtype == rrtype.A:
				return mkResp(t, q, func(b *wire.Builder) *wire.Builder {
					a := wire.NewRecord(wire.MustParseName("www.example."),
						60*time.Second,
						rdata.NewA(netip.MustParseAddr("192.0.2.55")))
					return b.Authoritative(true).Answer(a)
				}), nil
			}
			return mkResp(t, q, func(b *wire.Builder) *wire.Builder {
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
	entry, err := r.Resolve(rctx, wire.MustParseName("www.example."), rrtype.A)
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
				return mkResp(t, q, func(b *wire.Builder) *wire.Builder {
					ns := wire.NewRecord(wire.MustParseName("example."),
						60*time.Second,
						rdata.NewNS(wire.MustParseName("ns1.example.")))
					glue := wire.NewRecord(wire.MustParseName("ns1.example."),
						60*time.Second,
						rdata.NewAAAA(netip.MustParseAddr("2001:db8::1")))
					return b.Authority(ns).Additional(glue)
				}), nil
			}
			if server == child {
				a := wire.NewRecord(question.Name(), 60*time.Second,
					rdata.NewA(netip.MustParseAddr("192.0.2.7")))
				return mkResp(t, q, func(b *wire.Builder) *wire.Builder {
					return b.Authoritative(true).Answer(a)
				}), nil
			}
			return mkResp(t, q, func(b *wire.Builder) *wire.Builder {
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
	entry, err := r.Resolve(rctx, wire.MustParseName("www.example."), rrtype.A)
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
			return mkResp(t, q, func(b *wire.Builder) *wire.Builder {
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
	_, err := r.Resolve(rctx, wire.MustParseName("www.example."), rrtype.A)
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
			return mkResp(t, q, func(b *wire.Builder) *wire.Builder {
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
	_, err := r.Resolve(rctx, wire.MustParseName("nope.example."), rrtype.A)
	require.ErrorIs(t, err, recursive.ErrAllServersLame)
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
				return mkResp(t, q, func(b *wire.Builder) *wire.Builder {
					return b.RCODE(wire.RCODERefused)
				}), nil
			}
			question := q.Questions()[0]
			ans := wire.NewRecord(question.Name(), 60*time.Second,
				rdata.NewA(netip.MustParseAddr("192.0.2.1")))
			return mkResp(t, q, func(b *wire.Builder) *wire.Builder {
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
	entry, err := r.Resolve(rctx, wire.MustParseName("www.example."), rrtype.A)
	require.NoError(t, err)
	require.Equal(t, 1, len(entry.Answer()))
}

// TestQueryAnyAllError exercises the queryAny path where every server errors.
func TestQueryAnyAllError(t *testing.T) {
	t.Parallel()
	dialer := stubDialer{
		fn: func(_ context.Context, _ netip.AddrPort, _ wire.Message) (wire.Message, error) {
			return nil, errors.New("synthetic dial failure")
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
	_, err := r.Resolve(rctx, wire.MustParseName("www.example."), rrtype.A)
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
			return nil, errors.New("transient")
		},
	}
	r := mustRecursive(t,
		recursive.WithRoots(
			netip.MustParseAddrPort("127.0.0.1:1001"),
			netip.MustParseAddrPort("127.0.0.1:1002"),
		),
		recursive.WithDialer(dialer),
	)
	_, err := r.Resolve(rctx, wire.MustParseName("www.example."), rrtype.A)
	require.ErrorIs(t, err, context.Canceled)
}

// TestServeDNSWithAuthorityAndAdditional exercises the ServeDNS branches that
// copy Authority/Additional records and propagate non-NoError RCODEs and AD.
func TestServeDNSWithAuthorityAndAdditional(t *testing.T) {
	t.Parallel()
	dialer := stubDialer{
		fn: func(_ context.Context, _ netip.AddrPort, q wire.Message) (wire.Message, error) {
			question := q.Questions()[0]
			soa := wire.NewRecord(wire.MustParseName("example."), 30*time.Second,
				rdata.NewSOA(
					wire.MustParseName("ns.example."),
					wire.MustParseName("hm.example."),
					1, 60*time.Second, 60*time.Second, 60*time.Second, 30*time.Second))
			ns := wire.NewRecord(wire.MustParseName("example."), 60*time.Second,
				rdata.NewNS(wire.MustParseName("ns.example.")))
			glue := wire.NewRecord(wire.MustParseName("ns.example."), 60*time.Second,
				rdata.NewA(netip.MustParseAddr("192.0.2.1")))
			_ = question
			return mkResp(t, q, func(b *wire.Builder) *wire.Builder {
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

	q, err := wire.NewBuilder().
		ID(7).
		RecursionDesired(true).
		Question(wire.NewQuestion(wire.MustParseName("nope.example."), rrtype.A)).
		Build()
	require.NoError(t, err)
	ex, err := acidns.NewUDPExchanger(ctrl.Addr())
	require.NoError(t, err)
	qctx, qcancel := context.WithTimeout(ctx, 2*time.Second)
	defer qcancel()
	resp, err := ex.Exchange(qctx, q)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENXDomain, resp.Flags().RCODE())
	require.True(t, resp.Flags().AuthenticData())
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
			a := wire.NewRecord(question.Name(), 60*time.Second,
				rdata.NewA(netip.MustParseAddr("192.0.2.1")))
			return mkResp(t, q, func(b *wire.Builder) *wire.Builder {
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

	q, err := wire.NewBuilder().
		ID(8).
		RecursionDesired(true).
		Question(wire.NewQuestion(wire.MustParseName("www.example."), rrtype.A)).
		Build()
	require.NoError(t, err)
	ex, err := acidns.NewUDPExchanger(ctrl.Addr())
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
			a := wire.NewRecord(question.Name(), 60*time.Second,
				rdata.NewA(netip.MustParseAddr("192.0.2.1")))
			return mkResp(t, q, func(b *wire.Builder) *wire.Builder {
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
	_, err := r.Resolve(rctx, wire.MustParseName("www.example."), rrtype.A)
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
		resp, _ := wire.NewBuilder().
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
		a := wire.NewRecord(question.Name(), 60*time.Second,
			rdata.NewA(netip.MustParseAddr("192.0.2.99")))
		resp, _ := wire.NewBuilder().
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
	q, err := wire.NewBuilder().
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
		resp, _ := wire.NewBuilder().
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
	q, err := wire.NewBuilder().
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
			a := wire.NewRecord(question.Name(), 60*time.Second,
				rdata.NewA(netip.MustParseAddr("192.0.2.50")))
			return mkResp(t, q, func(b *wire.Builder) *wire.Builder {
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
	entry, err := r.Resolve(rctx, wire.MustParseName("www.example."), rrtype.A)
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
			cname := wire.NewRecord(question.Name(), 60*time.Second,
				rdata.NewCNAME(wire.MustParseName("alias.example.")))
			return mkResp(t, q, func(b *wire.Builder) *wire.Builder {
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
	entry, err := r.Resolve(rctx, wire.MustParseName("www.example."), rrtype.CNAME)
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
			// Record TTL = 5s, SOA MINIMUM = 30s → cache uses the smaller TTL.
			soa := wire.NewRecord(wire.MustParseName("example."), 5*time.Second,
				rdata.NewSOA(
					wire.MustParseName("ns.example."),
					wire.MustParseName("hm.example."),
					1, 60*time.Second, 60*time.Second, 60*time.Second, 30*time.Second))
			return mkResp(t, q, func(b *wire.Builder) *wire.Builder {
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
	entry, err := r.Resolve(rctx, wire.MustParseName("nope.example."), rrtype.A)
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
				cname := wire.NewRecord(question.Name(), 60*time.Second,
					rdata.NewCNAME(target))
				// AA=false to drive the hasAnswerFor branch.
				return mkResp(t, q, func(b *wire.Builder) *wire.Builder {
					return b.Answer(cname)
				}), nil
			}
			// Resolve the alias to an A.
			a := wire.NewRecord(question.Name(), 60*time.Second,
				rdata.NewA(netip.MustParseAddr("192.0.2.77")))
			return mkResp(t, q, func(b *wire.Builder) *wire.Builder {
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
	entry, err := r.Resolve(rctx, wire.MustParseName("www.example."), rrtype.A)
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
			ns := wire.NewRecord(wire.MustParseName("example."),
				60*time.Second,
				rdata.NewNS(wire.MustParseName("ns.example.")))
			glue := wire.NewRecord(wire.MustParseName("ns.example."),
				60*time.Second,
				rdata.NewA(netip.MustParseAddr("127.0.0.1")))
			return mkResp(t, q, func(b *wire.Builder) *wire.Builder {
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
	_, err := r.Resolve(rctx, wire.MustParseName("www.example."), rrtype.A)
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
			a := wire.NewRecord(question.Name(), 60*time.Second,
				rdata.NewA(netip.MustParseAddr("203.0.113.99")))
			return mkResp(t, q, func(b *wire.Builder) *wire.Builder {
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
			_, err := r.Resolve(rctx, wire.MustParseName("herd.example."), rrtype.A)
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
