package tcp_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient/transport"
	"github.com/lestrrat-go/acidns/dnsclient/transport/tcp"
	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/stretchr/testify/require"
)

func TestTCPStream(t *testing.T) {
	t.Parallel()
	addr := startTCPEcho(t)
	ex, err := tcp.New(addr, tcp.WithTimeout(2*time.Second))
	require.NoError(t, err)

	q, err := dnsmsg.NewBuilder().
		ID(0xc0de).
		Question(dnsmsg.NewQuestion(dnsname.MustParse("example.com"), rrtype.A)).
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
	q, _ := dnsmsg.NewBuilder().ID(1).
		Question(dnsmsg.NewQuestion(dnsname.MustParse("example.com"), rrtype.A)).
		Build()
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	se, ok := ex.(transport.StreamExchanger)
	require.True(t, ok)
	_, err = se.Stream(ctx, q)
	require.Error(t, err)
}
