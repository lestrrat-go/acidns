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

func TestTCPStream(t *testing.T) {
	t.Parallel()
	addr := startTCPEcho(t)
	ex, err := acidns.NewTCPExchanger(addr, acidns.WithTCPTimeout(2*time.Second))
	require.NoError(t, err)

	q, err := wire.NewMessageBuilder().
		ID(0xc0de).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	require.NoError(t, err)

	stream, err := ex.Stream(t.Context(), q)
	require.NoError(t, err)
	defer func() { _ = stream.Close() }()
	resp, err := stream.Next(t.Context())
	require.NoError(t, err)
	require.Equal(t, q.ID(), resp.ID())
}

func TestTCPNewInvalidAddr(t *testing.T) {
	t.Parallel()
	_, err := acidns.NewTCPExchanger(netip.AddrPort{})
	require.Error(t, err)
}

func TestTCPDialFailure(t *testing.T) {
	t.Parallel()
	ex, err := acidns.NewTCPExchanger(netip.MustParseAddrPort("127.0.0.1:1"))
	require.NoError(t, err)
	q, _ := wire.NewMessageBuilder().ID(1).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	_, err = ex.Stream(ctx, q)
	require.Error(t, err)
}
