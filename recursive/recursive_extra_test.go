package recursive_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/recursive"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// chainHandler answers an incoming query by chaining CNAMEs in a
// pre-defined order and returning a final A record at the tail.
type chainHandler struct {
	chain map[string]wire.Name // cname source → target
	final map[string]netip.Addr
}

func (h chainHandler) ServeDNS(_ context.Context, w acidns.ResponseWriter, q wire.Message) {
	question := q.Questions()[0]
	b := wire.NewMessageBuilder().
		ID(q.ID()).
		Response(true).
		Authoritative(true).
		Question(question)
	cur := question.Name()
	for range 16 {
		if next, ok := h.chain[cur.String()]; ok {
			b.Answer(wire.NewRecord(cur, time.Hour, rdata.MustNewCNAME(next)))
			cur = next
			continue
		}
		if a, ok := h.final[cur.String()]; ok {
			b.Answer(wire.NewRecord(cur, time.Hour, rdata.MustNewA(a)))
		}
		break
	}
	resp, _ := b.Build()
	_ = w.WriteMsg(resp)
}

func TestCNAMEChainFollowed(t *testing.T) {
	t.Parallel()
	h := chainHandler{
		chain: map[string]wire.Name{
			"www.example.": wire.MustParseName("alias.example."),
		},
		final: map[string]netip.Addr{
			"alias.example.": netip.MustParseAddr("192.0.2.99"),
		},
	}
	srv, err := acidns.NewUDPServer(netip.MustParseAddrPort("127.0.0.1:0"), h)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)

	require.NoError(t, err)

	r := mustRecursive(t, recursive.WithRoots(ctrl.Addr()))
	rctx, rcancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer rcancel()
	entry, err := r.Resolve(rctx, wire.MustParseName("www.example."), rrtype.A)
	require.NoError(t, err)
	// Walk the answer set: should contain the CNAME and the A.
	var sawA, sawCNAME bool
	for _, rec := range entry.Answer() {
		switch rec.Type() {
		case rrtype.A:
			sawA = true
		case rrtype.CNAME:
			sawCNAME = true
		}
	}
	require.True(t, sawCNAME, "expected CNAME in chain answer")
	require.True(t, sawA, "expected final A after CNAME chase")
}

func TestCNAMELoopDetected(t *testing.T) {
	t.Parallel()
	h := chainHandler{
		chain: map[string]wire.Name{
			"a.example.": wire.MustParseName("b.example."),
			"b.example.": wire.MustParseName("a.example."),
		},
	}
	srv, err := acidns.NewUDPServer(netip.MustParseAddrPort("127.0.0.1:0"), h)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)

	require.NoError(t, err)

	r := mustRecursive(t, recursive.WithRoots(ctrl.Addr()), recursive.WithMaxCNAMEDepth(4))
	rctx, rcancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer rcancel()
	_, err = r.Resolve(rctx, wire.MustParseName("a.example."), rrtype.A)
	require.ErrorIs(t, err, recursive.ErrCNAMELoop)
}

func TestLameServerSkipped(t *testing.T) {
	t.Parallel()
	// Two distinct auth servers serving the same zone. The
	// selectiveServfailDialer makes the bad address respond with
	// SERVFAIL; the resolver should fall through to the other server.
	good := startAuth(t, `$ORIGIN example.com.
$TTL 30
@   IN  SOA  ns. hm. ( 1 2 3 4 5 )
@   IN  NS   ns1.example.com.
ns1 IN  A    192.0.2.10
www IN  A    192.0.2.42
`)
	bad := startAuth(t, `$ORIGIN example.com.
$TTL 30
@   IN  SOA  ns. hm. ( 1 2 3 4 5 )
@   IN  NS   ns1.example.com.
ns1 IN  A    192.0.2.11
www IN  A    192.0.2.43
`)
	servfail := selectiveServfailDialer{
		delegate: recursive.DefaultDialer(),
		target:   bad,
	}

	r := mustRecursive(t,
		recursive.WithRoots(bad, good),
		recursive.WithDialer(servfail),
	)
	rctx, rcancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer rcancel()
	_, err := r.Resolve(rctx, wire.MustParseName("www.example.com"), rrtype.A)
	require.NoError(t, err)
}

// selectiveServfailDialer responds with SERVFAIL whenever asked to talk to
// `target`, and proxies anything else to delegate.
type selectiveServfailDialer struct {
	delegate recursive.Dialer
	target   netip.AddrPort
}

func (d selectiveServfailDialer) Exchange(ctx context.Context, server netip.AddrPort, q wire.Message) (wire.Message, error) {
	if server == d.target {
		question := q.Questions()[0]
		resp, _ := wire.NewMessageBuilder().
			ID(q.ID()).
			Response(true).
			RCODE(wire.RCODEServFail).
			Question(question).
			Build()
		return resp, nil
	}
	return d.delegate.Exchange(ctx, server, q)
}

// validatorStub implements recursive.Validator. It returns a fixed result.
type validatorStub struct {
	status recursive.ValidationStatus
	err    error
}

type validatorAnswer struct {
	status recursive.ValidationStatus
	reason error
}

func (a *validatorAnswer) Result() recursive.ValidationStatus { return a.status }
func (a *validatorAnswer) Records() []wire.Record             { return nil }
func (a *validatorAnswer) RCODE() wire.RCODE                  { return wire.RCODENoError }
func (a *validatorAnswer) Reason() error                      { return a.reason }

func (s validatorStub) Resolve(_ context.Context, _ wire.Name, _ rrtype.Type) (recursive.ValidationResult, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &validatorAnswer{status: s.status}, nil
}

func TestValidatorBogusReturnsServfail(t *testing.T) {
	t.Parallel()
	addr := startAuth(t, `$ORIGIN example.com.
$TTL 30
@   IN  SOA  ns. hm. ( 1 2 3 4 5 )
@   IN  NS   ns1.example.com.
ns1 IN  A    192.0.2.10
www IN  A    192.0.2.42
`)
	r := mustRecursive(t,
		recursive.WithRoots(addr),
		recursive.WithValidator(validatorStub{status: recursive.StatusBogus}),
	)
	rctx, rcancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer rcancel()
	_, err := r.Resolve(rctx, wire.MustParseName("www.example.com"), rrtype.A)
	require.Error(t, err)
}

func TestValidatorSecureSetsAD(t *testing.T) {
	t.Parallel()
	addr := startAuth(t, `$ORIGIN example.com.
$TTL 30
@   IN  SOA  ns. hm. ( 1 2 3 4 5 )
@   IN  NS   ns1.example.com.
ns1 IN  A    192.0.2.10
www IN  A    192.0.2.42
`)
	r := mustRecursive(t,
		recursive.WithRoots(addr),
		recursive.WithValidator(validatorStub{status: recursive.StatusSecure}),
	)
	rctx, rcancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer rcancel()
	entry, err := r.Resolve(rctx, wire.MustParseName("www.example.com"), rrtype.A)
	require.NoError(t, err)
	require.True(t, entry.AD())
}

func TestServerStatsTracksRTT(t *testing.T) {
	t.Parallel()
	addr := startAuth(t, `$ORIGIN example.com.
$TTL 30
@   IN  SOA  ns. hm. ( 1 2 3 4 5 )
@   IN  NS   ns1.example.com.
ns1 IN  A    192.0.2.10
www IN  A    192.0.2.42
`)
	stats := recursive.NewMemoryStats()
	r := mustRecursive(t,
		recursive.WithRoots(addr),
		recursive.WithServerStats(stats),
	)
	rctx, rcancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer rcancel()
	_, err := r.Resolve(rctx, wire.MustParseName("www.example.com"), rrtype.A)
	require.NoError(t, err)
	score := stats.Score(addr)
	require.Greater(t, score.RTT().Nanoseconds(), int64(0), "expected non-zero RTT recorded")
	require.Equal(t, 0, score.FailureStreak())
}

func TestQueryTimeoutSurvivesContextRespect(t *testing.T) {
	t.Parallel()
	// A handler that intentionally delays beyond the per-query timeout.
	slow := acidns.HandlerFunc(func(_ context.Context, w acidns.ResponseWriter, q wire.Message) {
		time.Sleep(100 * time.Millisecond)
		question := q.Questions()[0]
		resp, _ := wire.NewMessageBuilder().
			ID(q.ID()).
			Response(true).
			Authoritative(true).
			Question(question).
			Build()
		_ = w.WriteMsg(resp)
	})
	srv, err := acidns.NewUDPServer(netip.MustParseAddrPort("127.0.0.1:0"), slow)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)

	require.NoError(t, err)

	r := mustRecursive(t,
		recursive.WithRoots(ctrl.Addr()),
		recursive.WithQueryTimeout(20*time.Millisecond),
		recursive.WithMaxIterations(2),
	)
	rctx, rcancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer rcancel()
	_, err = r.Resolve(rctx, wire.MustParseName("www.example."), rrtype.A)
	require.Error(t, err)
}
