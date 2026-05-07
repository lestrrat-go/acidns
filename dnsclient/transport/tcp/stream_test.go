package tcp_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient/transport"
	"github.com/lestrrat-go/acidns/dnsclient/transport/tcp"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

func TestTCPStream(t *testing.T) {
	t.Parallel()
	addr := startTCPEcho(t)
	ex, err := tcp.New(addr, tcp.WithTimeout(2*time.Second))
	require.NoError(t, err)

	q, err := wire.NewBuilder().
		ID(0xc0de).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	require.NoError(t, err)

	se, ok := ex.(transport.StreamExchanger)
	require.True(t, ok)
	stream, err := se.Stream(t.Context(), q)
	require.NoError(t, err)
	defer stream.Close()
	resp, err := stream.Next(t.Context())
	require.NoError(t, err)
	require.Equal(t, q.ID(), resp.ID())
}

func TestTCPNewInvalidAddr(t *testing.T) {
	t.Parallel()
	_, err := tcp.New(netip.AddrPort{})
	require.Error(t, err)
}

func TestTCPDialFailure(t *testing.T) {
	t.Parallel()
	ex, err := tcp.New(netip.MustParseAddrPort("127.0.0.1:1"))
	require.NoError(t, err)
	q, _ := wire.NewBuilder().ID(1).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	se, ok := ex.(transport.StreamExchanger)
	require.True(t, ok)
	_, err = se.Stream(ctx, q)
	require.Error(t, err)
}
