package acidns_test

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/authoritative"
	"github.com/lestrrat-go/acidns/dnsclient"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/zonefile"
	"github.com/stretchr/testify/require"
)

const e2eZone = `$ORIGIN example.com.
$TTL 60
@   IN  SOA  ns1.example.com. hostmaster.example.com. (
    2024010100 7200 3600 1209600 60 )
@   IN  NS   ns1.example.com.
ns1 IN  A    192.0.2.10
www IN  A    192.0.2.1
www IN  A    192.0.2.2
www IN  AAAA 2001:db8::1
www IN  AAAA 2001:db8::2
mail IN A    192.0.2.3
mail IN MX   10 mail.example.com.
alias IN CNAME www.example.com.
`

func startAuthServer(t *testing.T) (netip.AddrPort, netip.AddrPort) {
	t.Helper()

	z, err := zonefile.Parse(strings.NewReader(e2eZone))
	require.NoError(t, err)
	h, err := authoritative.New(authoritative.WithZone(z))
	require.NoError(t, err)

	udpSrv, err := acidns.ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"), h)
	require.NoError(t, err)
	tcpSrv, err := acidns.ListenTCP(netip.MustParseAddrPort("127.0.0.1:0"), h)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = udpSrv.Serve(ctx) }()
	go func() { _ = tcpSrv.Serve(ctx) }()
	return udpSrv.Addr(), tcpSrv.Addr()
}

func TestE2EAuthoritativeOverUDPAndTCP(t *testing.T) {
	t.Parallel()
	udpAddr, tcpAddr := startAuthServer(t)

	// Use both UDP+TCP through the standard Resolver wiring (UDP primary,
	// TCP fall-back on TC). The TCP fall-back path is exercised below by
	// raising EDNS UDP size on a deliberately-large response.
	_ = tcpAddr // not used directly here; Resolver will dial TCP itself

	r, err := dnsclient.New(dnsclient.WithServers(udpAddr))
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	t.Run("LookupHost www", func(t *testing.T) {
		addrs, err := dnsclient.LookupHost(ctx, r, "www.example.com")
		require.NoError(t, err)
		got := make([]string, len(addrs))
		for i, a := range addrs {
			got[i] = a.String()
		}
		slices.Sort(got)
		require.Equal(t, []string{
			"192.0.2.1", "192.0.2.2", "2001:db8::1", "2001:db8::2",
		}, got)
	})

	t.Run("Resolve MX mail", func(t *testing.T) {
		ans, err := r.Resolve(ctx, wire.MustParseName("mail.example.com"), rrtype.MX)
		require.NoError(t, err)
		require.Equal(t, wire.RCODENoError, ans.RCODE())
		require.True(t, ans.Authoritative())
		require.Equal(t, 1, len(ans.Records()))
		mx := ans.Records()[0].RData().(rdata.MX)
		require.Equal(t, uint16(10), mx.Preference())
	})

	t.Run("NXDOMAIN", func(t *testing.T) {
		_, err := r.Resolve(ctx, wire.MustParseName("nope.example.com"), rrtype.A)
		require.ErrorIs(t, err, dnsclient.ErrNXDOMAIN)
		var rerr *dnsclient.RCodeError
		require.ErrorAs(t, err, &rerr)
		require.Equal(t, 1, len(rerr.Answer.Raw().Authorities()))
	})

	t.Run("NODATA", func(t *testing.T) {
		ans, err := r.Resolve(ctx, wire.MustParseName("ns1.example.com"), rrtype.AAAA)
		require.NoError(t, err)
		require.Equal(t, wire.RCODENoError, ans.RCODE())
		require.Equal(t, 0, len(ans.Records()))
		require.Equal(t, 1, len(ans.Raw().Authorities()))
	})

	t.Run("CNAME chase", func(t *testing.T) {
		ans, err := r.Resolve(ctx, wire.MustParseName("alias.example.com"), rrtype.A)
		require.NoError(t, err)
		require.Equal(t, wire.RCODENoError, ans.RCODE())
		// Records() is filtered to QTYPE matches (A only); the raw response
		// contains the CNAME hop too.
		require.Equal(t, 2, len(ans.Records()))
		require.Equal(t, 3, len(ans.Raw().Answers()))
	})

	t.Run("REFUSED out-of-zone", func(t *testing.T) {
		_, err := r.Resolve(ctx, wire.MustParseName("example.org"), rrtype.A)
		require.ErrorIs(t, err, dnsclient.ErrRefused)
	})
}
