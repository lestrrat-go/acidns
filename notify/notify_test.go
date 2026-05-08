package notify_test

import (
	"context"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/authoritative"
	"github.com/lestrrat-go/acidns/notify"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/zonefile"
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
	z, err := zonefile.Parse(strings.NewReader(notifyZone))
	require.NoError(t, err)
	a, err := authoritative.New(
		authoritative.WithZone(z),
		authoritative.WithNotifyHandler(h),
	)
	require.NoError(t, err)
	srv, err := acidns.NewUDPServer(netip.MustParseAddrPort("127.0.0.1:0"), a)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)

	require.NoError(t, err)
	return ctrl.Addr()
}

func TestSendNotifyAcks(t *testing.T) {
	t.Parallel()

	var fired atomic.Int32
	addr := startSecondary(t, func(_ wire.Question, _ acidns.ResponseWriter) {
		fired.Add(1)
	})

	ex, err := acidns.NewUDPExchanger(addr)
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
	ex, err := acidns.NewUDPExchanger(addr)
	require.NoError(t, err)
	resp, err := notify.Send(t.Context(), ex, wire.MustParseName("example.org"))
	require.NoError(t, err)
	require.Equal(t, wire.RCODENotAuth, resp.Flags().RCODE())
}
