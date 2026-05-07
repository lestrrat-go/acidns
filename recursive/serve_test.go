package recursive_test

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient/transport/udp"
	"github.com/lestrrat-go/acidns/dnsserver"
	"github.com/lestrrat-go/acidns/recursive"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

func TestServeDNSEndToEnd(t *testing.T) {
	t.Parallel()

	authAddr := startAuth(t, `$ORIGIN example.com.
$TTL 60
@   IN  SOA  ns1.example.com. hm.example.com. ( 1 2 3 4 5 )
@   IN  NS   ns1.example.com.
ns1 IN  A    192.0.2.10
www IN  A    192.0.2.42
`)
	cache := recursive.NewMemoryCache()
	r := recursive.New(
		recursive.WithRoots(authAddr),
		recursive.WithCache(cache),
		recursive.WithMaxIterations(50),
	)
	srv, err := dnsserver.ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"), r)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx) }()

	ex, err := udp.New(srv.Addr())
	require.NoError(t, err)
	q, err := wire.NewBuilder().
		ID(0xbeef).
		Question(wire.NewQuestion(wire.MustParseName("www.example.com"), rrtype.A)).
		RecursionDesired(true).
		Build()
	require.NoError(t, err)

	qctx, qcancel := context.WithTimeout(ctx, 5*time.Second)
	defer qcancel()
	resp, err := ex.Exchange(qctx, q)
	require.NoError(t, err)
	require.True(t, resp.Flags().Response())
	require.True(t, resp.Flags().RecursionAvailable())
	require.Equal(t, 1, len(resp.Answers()))
}

func TestServeDNSFormErrOnEmptyQuestion(t *testing.T) {
	t.Parallel()
	r := recursive.New(recursive.WithRoots(netip.MustParseAddrPort("127.0.0.1:65535")))
	srv, err := dnsserver.ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"), r)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx) }()

	q, err := wire.NewBuilder().ID(1).Build() // no question
	require.NoError(t, err)
	ex, err := udp.New(srv.Addr())
	require.NoError(t, err)
	qctx, qcancel := context.WithTimeout(ctx, 2*time.Second)
	defer qcancel()
	resp, err := ex.Exchange(qctx, q)
	require.NoError(t, err)
	require.Equal(t, wire.RCODEFormErr, resp.Flags().RCODE())
}

func TestServeDNSServFailOnUnreachable(t *testing.T) {
	t.Parallel()
	// Roots that immediately refuse — quick error path through Resolve.
	r := recursive.New(
		recursive.WithRoots(netip.MustParseAddrPort("127.0.0.1:1")),
		recursive.WithMaxIterations(1),
	)
	srv, err := dnsserver.ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"), r)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx) }()

	q, err := wire.NewBuilder().
		ID(2).
		Question(wire.NewQuestion(wire.MustParseName("nope.invalid"), rrtype.A)).
		Build()
	require.NoError(t, err)
	ex, err := udp.New(srv.Addr())
	require.NoError(t, err)
	qctx, qcancel := context.WithTimeout(ctx, 2*time.Second)
	defer qcancel()
	resp, err := ex.Exchange(qctx, q)
	require.NoError(t, err)
	require.Equal(t, wire.RCODEServFail, resp.Flags().RCODE())
}

// trim used in helper above to avoid unused-import linter complaints.
var _ = strings.TrimSpace
