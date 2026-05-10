package axfr_test

import (
	"context"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/authoritative"
	"github.com/lestrrat-go/acidns/axfr"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/zonefile"
	"github.com/stretchr/testify/require"
)

const transferZone = `$ORIGIN example.com.
$TTL 60
@   IN  SOA  ns1.example.com. hostmaster.example.com. (
    2024010100 7200 3600 1209600 60 )
@   IN  NS   ns1.example.com.
ns1 IN  A    192.0.2.10
www IN  A    192.0.2.1
www IN  AAAA 2001:db8::1
mail IN A    192.0.2.3
mail IN MX   10 mail.example.com.
`

func newStreamEx(t *testing.T, addr netip.AddrPort) acidns.StreamExchanger {
	t.Helper()
	ex, err := acidns.NewTCPExchanger(addr)
	require.NoError(t, err)
	return ex
}

func TestTransferRoundTrip(t *testing.T) {
	t.Parallel()

	z, err := zonefile.Parse(strings.NewReader(transferZone))
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

	xferCtx, xcancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer xcancel()
	xfer, err := axfr.Start(xferCtx, newStreamEx(t, ctrl.Addr()), wire.MustParseName("example.com"))
	require.NoError(t, err)
	defer func() { _ = xfer.Close() }()

	var records []wire.Record
	for {
		ev, err := xfer.Next(xferCtx)
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		records = append(records, ev.Record())
	}
	require.GreaterOrEqual(t, len(records), 3)

	require.Equal(t, rrtype.SOA, records[0].Type())
	require.Equal(t, rrtype.SOA, records[len(records)-1].Type())

	var hasA, hasMX bool
	for _, r := range records[1 : len(records)-1] {
		switch r.Type() {
		case rrtype.A:
			hasA = true
		case rrtype.MX:
			hasMX = true
		}
	}
	require.True(t, hasA && hasMX)
}

func TestTransferRefusedOutOfZone(t *testing.T) {
	t.Parallel()

	z, err := zonefile.Parse(strings.NewReader(transferZone))
	require.NoError(t, err)
	h, _ := authoritative.New(authoritative.WithZone(z))
	srv, err := acidns.NewTCPServer(netip.MustParseAddrPort("127.0.0.1:0"), h)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)

	require.NoError(t, err)

	xfer, err := axfr.Start(t.Context(), newStreamEx(t, ctrl.Addr()), wire.MustParseName("example.org"))
	if err == nil {
		// Some servers send a single SERVFAIL/REFUSED message — the recReader
		// surfaces that as an error on the first Next call.
		defer func() { _ = xfer.Close() }()
		_, err = xfer.Next(t.Context())
	}
	require.Error(t, err)
}
