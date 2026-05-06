package ixfr_test

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient/ixfr"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/lestrrat-go/acidns/dnsserver"
	"github.com/lestrrat-go/acidns/dnsserver/authoritative"
	"github.com/lestrrat-go/acidns/dnszone"
	"github.com/stretchr/testify/require"
)

const ixfrZone = `$ORIGIN example.com.
$TTL 60
@   IN  SOA  ns1.example.com. hm.example.com. (
    100 7200 3600 1209600 60 )
@   IN  NS   ns1.example.com.
ns1 IN  A    192.0.2.10
www IN  A    192.0.2.42
`

func TestTransferAXFRFallback(t *testing.T) {
	t.Parallel()

	z, err := dnszone.Parse(strings.NewReader(ixfrZone))
	require.NoError(t, err)
	h, err := authoritative.New(authoritative.WithZone(z))
	require.NoError(t, err)

	srv, err := dnsserver.ListenTCP(netip.MustParseAddrPort("127.0.0.1:0"), h)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx) }()

	// Ask for the zone with a stale serial — server falls back to AXFR.
	clientSOA := rdata.NewSOA(
		dnsname.MustParse("ns1.example.com"),
		dnsname.MustParse("hm.example.com"),
		1, 7200*time.Second, 3600*time.Second, 1209600*time.Second, 60*time.Second)

	xferCtx, xcancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer xcancel()
	res, err := ixfr.Transfer(xferCtx, srv.Addr(), dnsname.MustParse("example.com"), clientSOA)
	require.NoError(t, err)
	require.Equal(t, ixfr.KindAXFRFallback, res.Kind)
	require.GreaterOrEqual(t, len(res.Records), 4)
	require.Equal(t, uint32(100), res.NewSOA.Serial())
}
