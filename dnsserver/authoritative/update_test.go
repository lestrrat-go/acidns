package authoritative_test

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient/dnsupdate"
	"github.com/lestrrat-go/acidns/dnsclient/transport/udp"
	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/lestrrat-go/acidns/dnsserver"
	"github.com/lestrrat-go/acidns/dnsserver/authoritative"
	"github.com/lestrrat-go/acidns/dnszone"
	"github.com/stretchr/testify/require"
)

const updateZone = `$ORIGIN example.com.
$TTL 60
@   IN  SOA  ns1.example.com. hm.example.com. ( 1 2 3 4 5 )
@   IN  NS   ns1.example.com.
ns1 IN  A    192.0.2.10
www IN  A    192.0.2.42
`

func startUpdatable(t *testing.T) (authoritative.Authoritative, netip.AddrPort) {
	t.Helper()
	z, err := dnszone.Parse(strings.NewReader(updateZone))
	require.NoError(t, err)
	a, err := authoritative.New(authoritative.WithZone(z))
	require.NoError(t, err)
	srv, err := dnsserver.ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"), a)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx) }()
	return a, srv.Addr()
}

func TestUpdateAddRRset(t *testing.T) {
	t.Parallel()
	a, addr := startUpdatable(t)

	// Add new record at "blog.example.com".
	new := dnsmsg.NewRecord(dnsname.MustParse("blog.example.com"), 60*time.Second,
		rdata.NewA(netip.MustParseAddr("198.51.100.5")))

	ex, err := udp.New(addr)
	require.NoError(t, err)
	msg, err := dnsupdate.NewBuilder(dnsname.MustParse("example.com")).
		AddRRset(new).
		Build()
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), msg)
	require.NoError(t, err)
	require.Equal(t, dnsmsg.RCODENoError, resp.Flags().RCODE())

	// Verify the new record appears in subsequent queries.
	q, _ := dnsmsg.NewBuilder().
		ID(2).
		Question(dnsmsg.NewQuestion(dnsname.MustParse("blog.example.com"), rrtype.A)).
		Build()
	r2, err := ex.Exchange(t.Context(), q)
	require.NoError(t, err)
	require.Equal(t, 1, len(r2.Answers()))
	require.Equal(t, "198.51.100.5", r2.Answers()[0].RData().(rdata.A).Addr().String())
	_ = a
}

func TestUpdateDeleteRRset(t *testing.T) {
	t.Parallel()
	_, addr := startUpdatable(t)

	ex, err := udp.New(addr)
	require.NoError(t, err)
	msg, err := dnsupdate.NewBuilder(dnsname.MustParse("example.com")).
		DeleteRRset(dnsname.MustParse("www.example.com"), rrtype.A).
		Build()
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), msg)
	require.NoError(t, err)
	require.Equal(t, dnsmsg.RCODENoError, resp.Flags().RCODE())

	// Now www.example.com should NXDOMAIN (we don't keep namesExist after delete) or NODATA.
	q, _ := dnsmsg.NewBuilder().
		ID(3).
		Question(dnsmsg.NewQuestion(dnsname.MustParse("www.example.com"), rrtype.A)).
		Build()
	r, err := ex.Exchange(t.Context(), q)
	require.NoError(t, err)
	require.Equal(t, 0, len(r.Answers()))
}

func TestUpdatePrereqRRsetExistsFails(t *testing.T) {
	t.Parallel()
	_, addr := startUpdatable(t)

	ex, err := udp.New(addr)
	require.NoError(t, err)
	msg, err := dnsupdate.NewBuilder(dnsname.MustParse("example.com")).
		PrereqRRsetExists(dnsname.MustParse("nope.example.com"), rrtype.A).
		AddRRset(dnsmsg.NewRecord(dnsname.MustParse("blog.example.com"), 60*time.Second,
			rdata.NewA(netip.MustParseAddr("198.51.100.7")))).
		Build()
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), msg)
	require.NoError(t, err)
	require.Equal(t, dnsmsg.RCODENXRRSet, resp.Flags().RCODE())
}

func TestUpdatePrereqRRsetAbsentSucceeds(t *testing.T) {
	t.Parallel()
	_, addr := startUpdatable(t)

	ex, err := udp.New(addr)
	require.NoError(t, err)
	msg, err := dnsupdate.NewBuilder(dnsname.MustParse("example.com")).
		PrereqRRsetAbsent(dnsname.MustParse("blog.example.com"), rrtype.A).
		AddRRset(dnsmsg.NewRecord(dnsname.MustParse("blog.example.com"), 60*time.Second,
			rdata.NewA(netip.MustParseAddr("198.51.100.8")))).
		Build()
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), msg)
	require.NoError(t, err)
	require.Equal(t, dnsmsg.RCODENoError, resp.Flags().RCODE())
}

func TestUpdateOutOfZoneRefused(t *testing.T) {
	t.Parallel()
	_, addr := startUpdatable(t)
	ex, err := udp.New(addr)
	require.NoError(t, err)
	msg, err := dnsupdate.NewBuilder(dnsname.MustParse("example.org")).
		AddRRset(dnsmsg.NewRecord(dnsname.MustParse("a.example.org"), 60*time.Second,
			rdata.NewA(netip.MustParseAddr("198.51.100.9")))).
		Build()
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), msg)
	require.NoError(t, err)
	require.Equal(t, dnsmsg.RCODENotAuth, resp.Flags().RCODE())
}
