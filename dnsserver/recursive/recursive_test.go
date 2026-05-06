package recursive_test

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/lestrrat-go/acidns/dnsserver"
	"github.com/lestrrat-go/acidns/dnsserver/authoritative"
	"github.com/lestrrat-go/acidns/dnsserver/recursive"
	"github.com/lestrrat-go/acidns/dnszone"
	"github.com/stretchr/testify/require"
)

// startAuth spawns an authoritative server bound to 127.0.0.1:0 and returns
// the bound address. Each test gets its own pair (root, child) and configures
// the recursive resolver against the root.
func startAuth(t *testing.T, zoneText string) netip.AddrPort {
	t.Helper()
	z, err := dnszone.Parse(strings.NewReader(zoneText))
	require.NoError(t, err)
	h, err := authoritative.New(authoritative.WithZone(z))
	require.NoError(t, err)
	srv, err := dnsserver.ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"), h)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx) }()
	return srv.Addr()
}

func TestResolveOneDelegationWithGlue(t *testing.T) {
	t.Parallel()

	// "child" zone for example.com.
	childAddr := startAuth(t, `$ORIGIN example.com.
$TTL 60
@   IN  SOA  ns1.example.com. hm.example.com. ( 1 2 3 4 5 )
@   IN  NS   ns1.example.com.
ns1 IN  A    192.0.2.10
www IN  A    192.0.2.42
`)

	// Pointing the resolver directly at the child auth server: the response
	// is authoritative on the first hop, exercising the no-delegation path.
	// True delegation is exercised in TestRealDelegation.
	r := recursive.New(recursive.WithRoots(childAddr))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	entry, err := r.Resolve(ctx, dnsname.MustParse("www.example.com"), rrtype.A)
	require.NoError(t, err)
	require.Equal(t, dnsmsg.RCODENoError, entry.RCODE)
	require.True(t, entry.AA)
	require.Equal(t, 1, len(entry.Answer))
	a := entry.Answer[0].RData().(rdata.A)
	require.Equal(t, "192.0.2.42", a.Addr().String())
}

// TestRealDelegation drives a true two-step iteration: a custom root
// returns a referral; a separate child authoritative answers the query.
// A test Dialer rewrites the resolver's outbound port so glue addresses
// resolve to the dynamically-bound test port.
func TestRealDelegation(t *testing.T) {
	t.Parallel()

	childAddr := startAuth(t, `$ORIGIN example.com.
$TTL 60
@   IN  SOA  ns1.example.com. hm.example.com. ( 1 2 3 4 5 )
@   IN  NS   ns1.example.com.
ns1 IN  A    127.0.0.1
www IN  A    192.0.2.55
`)

	// Root handler: a small in-process Handler that returns a fixed
	// referral pointing at ns1.example.com with 127.0.0.1 as glue.
	rootHandler := dnsserver.HandlerFunc(func(_ context.Context, w dnsserver.ResponseWriter, q dnsmsg.Message) {
		question := q.Questions()[0]
		ns := dnsmsg.NewRecord(dnsname.MustParse("example.com"), 60*time.Second,
			rdata.NewNS(dnsname.MustParse("ns1.example.com")))
		glue := dnsmsg.NewRecord(dnsname.MustParse("ns1.example.com"), 60*time.Second,
			rdata.NewA(netip.MustParseAddr("127.0.0.1")))
		resp, _ := dnsmsg.NewBuilder().
			ID(q.ID()).
			Response(true).
			Question(question).
			Authority(ns).
			Additional(glue).
			Build()
		_ = w.WriteMsg(resp)
	})
	rootSrv, err := dnsserver.ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"), rootHandler)
	require.NoError(t, err)
	rctx, rcancel := context.WithCancel(t.Context())
	t.Cleanup(rcancel)
	go func() { _ = rootSrv.Serve(rctx) }()

	// Custom Dialer: when the resolver tries to contact 127.0.0.1:53 (the
	// glue address with the default port), redirect to the child server's
	// actual port.
	dialer := portRewriteDialer{
		rewrites: map[netip.AddrPort]netip.AddrPort{
			netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 53): childAddr,
		},
	}

	r := recursive.New(
		recursive.WithRoots(rootSrv.Addr()),
		recursive.WithDialer(dialer),
	)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	entry, err := r.Resolve(ctx, dnsname.MustParse("www.example.com"), rrtype.A)
	require.NoError(t, err)
	require.Equal(t, dnsmsg.RCODENoError, entry.RCODE)
	require.True(t, entry.AA)
	require.Equal(t, 1, len(entry.Answer))
	require.Equal(t, "192.0.2.55", entry.Answer[0].RData().(rdata.A).Addr().String())
}

type portRewriteDialer struct {
	rewrites map[netip.AddrPort]netip.AddrPort
}

func (d portRewriteDialer) Exchange(ctx context.Context, server netip.AddrPort, q dnsmsg.Message) (dnsmsg.Message, error) {
	if mapped, ok := d.rewrites[server]; ok {
		server = mapped
	}
	return recursive.DefaultDialer().Exchange(ctx, server, q)
}

func TestCacheReturnsSameEntry(t *testing.T) {
	t.Parallel()
	addr := startAuth(t, `$ORIGIN example.com.
$TTL 30
@   IN  SOA  ns. hm. ( 1 2 3 4 5 )
@   IN  NS   ns1.example.com.
ns1 IN  A    192.0.2.10
www IN  A    192.0.2.42
`)
	r := recursive.New(recursive.WithRoots(addr))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	a, err := r.Resolve(ctx, dnsname.MustParse("www.example.com"), rrtype.A)
	require.NoError(t, err)
	b, err := r.Resolve(ctx, dnsname.MustParse("www.example.com"), rrtype.A)
	require.NoError(t, err)
	require.Equal(t, a.ExpiresAt, b.ExpiresAt, "second lookup must come from cache")
}

func TestNXDOMAINCached(t *testing.T) {
	t.Parallel()
	addr := startAuth(t, `$ORIGIN example.com.
$TTL 30
@   IN  SOA  ns. hm. ( 1 2 3 4 5 )
@   IN  NS   ns1.example.com.
ns1 IN  A    192.0.2.10
`)
	r := recursive.New(recursive.WithRoots(addr))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	entry, err := r.Resolve(ctx, dnsname.MustParse("nope.example.com"), rrtype.A)
	require.NoError(t, err)
	require.Equal(t, dnsmsg.RCODENXDomain, entry.RCODE)
	// SOA MINIMUM is 5s, the smallest cap so negative TTL must be ≤ 5s.
	require.LessOrEqual(t, time.Until(entry.ExpiresAt), 5*time.Second+time.Second)
}

func TestNODATACachedRespectsSOAMinimum(t *testing.T) {
	t.Parallel()
	addr := startAuth(t, `$ORIGIN example.com.
$TTL 600
@    IN SOA ns. hm. ( 1 2 3 4 7 )
@    IN NS  ns1.example.com.
ns1  IN A   192.0.2.10
www  IN A   192.0.2.20
`)
	r := recursive.New(recursive.WithRoots(addr))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	// www has A but not AAAA — NODATA. SOA MINIMUM=7s caps the negative
	// cache TTL even though everything else (TTL=600) is much higher.
	entry, err := r.Resolve(ctx, dnsname.MustParse("www.example.com"), rrtype.AAAA)
	require.NoError(t, err)
	require.Equal(t, dnsmsg.RCODENoError, entry.RCODE)
	require.Equal(t, 0, len(entry.Answer))
	require.LessOrEqual(t, time.Until(entry.ExpiresAt), 8*time.Second)
}
