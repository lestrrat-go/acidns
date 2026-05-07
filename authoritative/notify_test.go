package authoritative_test

import (
	"context"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient/transport/udp"
	"github.com/lestrrat-go/acidns/dnsserver"
	"github.com/lestrrat-go/acidns/authoritative"
	"github.com/lestrrat-go/acidns/zonefile"
	"github.com/lestrrat-go/acidns/notify"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/stretchr/testify/require"
)

const notifyZone = `$ORIGIN example.com.
$TTL 60
@   IN  SOA  ns1.example.com. hm.example.com. ( 1 2 3 4 5 )
@   IN  NS   ns1.example.com.
ns1 IN  A    192.0.2.10
`

func TestServeNotifyAcksAndCallsHandler(t *testing.T) {
	t.Parallel()

	z, err := zonefile.Parse(strings.NewReader(notifyZone))
	require.NoError(t, err)

	var fired atomic.Int32
	h, err := authoritative.New(
		authoritative.WithZone(z),
		authoritative.WithNotifyHandler(func(_ wire.Question, _ dnsserver.ResponseWriter) {
			fired.Add(1)
		}),
	)
	require.NoError(t, err)

	srv, err := dnsserver.ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"), h)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx) }()

	ex, err := udp.New(srv.Addr())
	require.NoError(t, err)
	resp, err := notify.Send(t.Context(), ex, wire.MustParseName("example.com"))
	require.NoError(t, err)
	require.True(t, resp.Flags().Authoritative())
	require.Eventually(t, func() bool { return fired.Load() == 1 }, time.Second, 10*time.Millisecond)
}

func TestServeNotifyRefusesUnknownZone(t *testing.T) {
	t.Parallel()
	z, err := zonefile.Parse(strings.NewReader(notifyZone))
	require.NoError(t, err)
	h, err := authoritative.New(authoritative.WithZone(z))
	require.NoError(t, err)
	srv, err := dnsserver.ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"), h)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx) }()

	ex, err := udp.New(srv.Addr())
	require.NoError(t, err)
	resp, err := notify.Send(t.Context(), ex, wire.MustParseName("example.org"))
	require.NoError(t, err)
	require.Equal(t, wire.RCODENotAuth, resp.Flags().RCODE())
}

func TestZonesAccessor(t *testing.T) {
	t.Parallel()
	z, err := zonefile.Parse(strings.NewReader(notifyZone))
	require.NoError(t, err)
	h, err := authoritative.New(authoritative.WithZone(z))
	require.NoError(t, err)
	zones := h.Zones()
	require.Len(t, zones, 1)
}
