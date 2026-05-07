package dnsserver_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient/transport/tcp"
	"github.com/lestrrat-go/acidns/dnsclient/transport/udp"
	"github.com/lestrrat-go/acidns/dnsserver"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

type echoHandler struct{}

func (echoHandler) ServeDNS(_ context.Context, w dnsserver.ResponseWriter, q wire.Message) {
	resp, _ := wire.NewBuilder().ID(q.ID()).Response(true).Question(q.Questions()[0]).Build()
	_ = w.WriteMsg(resp)
}

func TestUDPListenWithOptions(t *testing.T) {
	t.Parallel()
	srv, err := dnsserver.ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"), echoHandler{},
		dnsserver.WithUDPReadBuffer(4096),
		dnsserver.WithUDPMaxResponse(1232),
	)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx) }()

	ex, err := udp.New(srv.Addr())
	require.NoError(t, err)
	q, _ := wire.NewBuilder().
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
	srv, err := dnsserver.ListenTCP(netip.MustParseAddrPort("127.0.0.1:0"), echoHandler{},
		dnsserver.WithTCPIdleTimeout(2*time.Second),
	)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx) }()

	ex, err := tcp.New(srv.Addr())
	require.NoError(t, err)
	q, _ := wire.NewBuilder().
		ID(2).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	qctx, qcancel := context.WithTimeout(ctx, 2*time.Second)
	defer qcancel()
	resp, err := ex.Exchange(qctx, q)
	require.NoError(t, err)
	require.Equal(t, uint16(2), resp.ID())
}
