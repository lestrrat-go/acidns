package ixfr_test

import (
	"context"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/authoritative"
	"github.com/lestrrat-go/acidns/ixfr"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/zonefile"
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

	z, err := zonefile.Parse(strings.NewReader(ixfrZone))
	require.NoError(t, err)
	h, err := authoritative.New(
		authoritative.WithZone(z),
		authoritative.WithAXFRPolicy(func(_ context.Context, _ acidns.ResponseWriter, _ wire.Message) bool { return true }),
	)
	require.NoError(t, err)

	srv, err := acidns.NewTCPServer(netip.MustParseAddrPort("127.0.0.1:0"), h)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)

	require.NoError(t, err)

	// Ask for the zone with a stale serial — server falls back to AXFR.
	clientSOA := rdata.MustNewSOA(
		wire.MustParseName("ns1.example.com"),
		wire.MustParseName("hm.example.com"),
		1, 7200*time.Second, 3600*time.Second, 1209600*time.Second, 60*time.Second)

	xferCtx, xcancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer xcancel()

	ex, err := acidns.NewTCPClient(ctrl.Addr())
	require.NoError(t, err)

	xfer, err := ixfr.Start(xferCtx, ex, wire.MustParseName("example.com"), clientSOA)
	require.NoError(t, err)
	defer func() { _ = xfer.Close() }()

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
