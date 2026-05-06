package axfr_test

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient/axfr"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/lestrrat-go/acidns/dnsserver"
	"github.com/lestrrat-go/acidns/dnsserver/authoritative"
	"github.com/lestrrat-go/acidns/dnszone"
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

func TestTransferRoundTrip(t *testing.T) {
	t.Parallel()

	z, err := dnszone.Parse(strings.NewReader(transferZone))
	require.NoError(t, err)
	h, err := authoritative.New(authoritative.WithZone(z))
	require.NoError(t, err)

	srv, err := dnsserver.ListenTCP(netip.MustParseAddrPort("127.0.0.1:0"), h)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx) }()

	xferCtx, xcancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer xcancel()
	records, err := axfr.Transfer(xferCtx, srv.Addr(), dnsname.MustParse("example.com"))
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(records), 3)

	// First and last must be SOA.
	require.Equal(t, rrtype.SOA, records[0].Type())
	require.Equal(t, rrtype.SOA, records[len(records)-1].Type())

	// Body should contain at least one A and the MX.
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

	z, err := dnszone.Parse(strings.NewReader(transferZone))
	require.NoError(t, err)
	h, _ := authoritative.New(authoritative.WithZone(z))
	srv, err := dnsserver.ListenTCP(netip.MustParseAddrPort("127.0.0.1:0"), h)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx) }()

	_, err = axfr.Transfer(t.Context(), srv.Addr(), dnsname.MustParse("example.org"))
	require.Error(t, err)
}
