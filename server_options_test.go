package acidns_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

type echoHandler struct{}

func (echoHandler) ServeDNS(_ context.Context, w acidns.ResponseWriter, q wire.Message) {
	resp, _ := wire.NewMessageBuilder().ID(q.ID()).Response(true).Question(q.Questions()[0]).Build()
	_ = w.WriteMsg(resp)
}

func TestUDPListenWithOptions(t *testing.T) {
	t.Parallel()
	srv, err := acidns.NewUDPServer(netip.MustParseAddrPort("127.0.0.1:0"), echoHandler{},
		acidns.WithUDPListenerBufferSize(4096),
		acidns.WithUDPMaxResponse(1232),
	)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)

	require.NoError(t, err)

	ex, err := acidns.NewUDPExchanger(ctrl.Addr())
	require.NoError(t, err)
	q, _ := wire.NewMessageBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	qctx, qcancel := context.WithTimeout(ctx, 2*time.Second)
	defer qcancel()
	resp, err := ex.Exchange(qctx, q)
	require.NoError(t, err)
	require.Equal(t, uint16(1), resp.ID())
}

func TestTCPListenWithOptions(t *testing.T) {
	t.Parallel()
	srv, err := acidns.NewTCPServer(netip.MustParseAddrPort("127.0.0.1:0"), echoHandler{},
		acidns.WithTCPIdleTimeout(2*time.Second),
	)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)

	require.NoError(t, err)

	ex, err := acidns.NewTCPExchanger(ctrl.Addr())
	require.NoError(t, err)
	q, _ := wire.NewMessageBuilder().
		ID(2).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	qctx, qcancel := context.WithTimeout(ctx, 2*time.Second)
	defer qcancel()
	resp, err := ex.Exchange(qctx, q)
	require.NoError(t, err)
	require.Equal(t, uint16(2), resp.ID())
}
