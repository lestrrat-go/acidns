package notify_test

import (
	"context"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient/notify"
	"github.com/lestrrat-go/acidns/dnsclient/transport/udp"
	"github.com/lestrrat-go/acidns/dnsserver"
	"github.com/lestrrat-go/acidns/dnsserver/authoritative"
	"github.com/lestrrat-go/acidns/dnszone"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/stretchr/testify/require"
)

const notifyZone = `$ORIGIN example.com.
$TTL 60
@   IN  SOA  ns1.example.com. hm.example.com. ( 1 2 3 4 5 )
@   IN  NS   ns1.example.com.
ns1 IN  A    192.0.2.10
`

func startSecondary(t *testing.T, h authoritative.NotifyHandler) netip.AddrPort {
	t.Helper()
	z, err := dnszone.Parse(strings.NewReader(notifyZone))
	require.NoError(t, err)
	a, err := authoritative.New(
		authoritative.WithZone(z),
		authoritative.WithNotifyHandler(h),
	)
	require.NoError(t, err)
	srv, err := dnsserver.ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"), a)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx) }()
	return srv.Addr()
}

func TestSendNotifyAcks(t *testing.T) {
	t.Parallel()

	var fired atomic.Int32
	addr := startSecondary(t, func(_ wire.Question, _ dnsserver.ResponseWriter) {
		fired.Add(1)
	})

	ex, err := udp.New(addr)
	require.NoError(t, err)
	resp, err := notify.Send(t.Context(), ex, wire.MustParseName("example.com"))
	require.NoError(t, err)
	require.Equal(t, wire.OpcodeNotify, resp.Flags().Opcode())
	require.True(t, resp.Flags().Response())
	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())

	// Give the handler time to fire (it runs after WriteMsg returns).
	require.Eventually(t, func() bool { return fired.Load() == 1 },
		1*time.Second, 10*time.Millisecond)
}

func TestNotifyForUnservedZoneNotAuth(t *testing.T) {
	t.Parallel()
	addr := startSecondary(t, nil)
	ex, err := udp.New(addr)
	require.NoError(t, err)
	resp, err := notify.Send(t.Context(), ex, wire.MustParseName("example.org"))
	require.NoError(t, err)
	require.Equal(t, wire.RCODENotAuth, resp.Flags().RCODE())
}
