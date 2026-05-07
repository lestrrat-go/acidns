package ixfr_test

import (
	"context"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient/transport"
	"github.com/lestrrat-go/acidns/dnsclient/transport/tcp"
	"github.com/lestrrat-go/acidns/dnsserver"
	"github.com/lestrrat-go/acidns/dnsserver/authoritative"
	"github.com/lestrrat-go/acidns/dnszone"
	"github.com/lestrrat-go/acidns/ixfr"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
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
		wire.MustParseName("ns1.example.com"),
		wire.MustParseName("hm.example.com"),
		1, 7200*time.Second, 3600*time.Second, 1209600*time.Second, 60*time.Second)

	xferCtx, xcancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer xcancel()

	ex, err := tcp.New(srv.Addr())
	require.NoError(t, err)
	sx, ok := ex.(transport.StreamExchanger)
	require.True(t, ok, "tcp exchanger must implement StreamExchanger")

	xfer, err := ixfr.Start(xferCtx, sx, wire.MustParseName("example.com"), clientSOA)
	require.NoError(t, err)
	defer xfer.Close()

	require.Equal(t, ixfr.KindAXFRFallback, xfer.Kind())
	require.Equal(t, uint32(100), xfer.NewSOA().Serial())

	count := 0
	for {
		ev, err := xfer.Next(xferCtx)
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		_, ok := ev.(ixfr.RecordEvent)
		require.True(t, ok, "AXFR-fallback events must be RecordEvent")
		count++
	}
	require.GreaterOrEqual(t, count, 4)
}
