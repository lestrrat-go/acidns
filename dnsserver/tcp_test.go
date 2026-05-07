package dnsserver_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient/transport/tcp"
	"github.com/lestrrat-go/acidns/dnsserver"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

func startTCP(t *testing.T, h dnsserver.Handler, opts ...dnsserver.TCPOption) dnsserver.Server {
	t.Helper()
	srv, err := dnsserver.ListenTCP(netip.MustParseAddrPort("127.0.0.1:0"), h, opts...)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	go func() { _ = srv.Serve(ctx) }()
	t.Cleanup(cancel)
	return srv
}

func TestTCPServerEcho(t *testing.T) {
	t.Parallel()

	h := dnsserver.HandlerFunc(func(_ context.Context, w dnsserver.ResponseWriter, q wire.Message) {
		ans := wire.NewRecord(q.Questions()[0].Name(), time.Minute,
			rdata.NewA(netip.MustParseAddr("203.0.113.88")))
		resp, _ := wire.NewBuilder().
			ID(q.ID()).
			Response(true).
			Question(q.Questions()[0]).
			Answer(ans).
			Build()
		_ = w.WriteMsg(resp)
	})
	srv := startTCP(t, h)

	ex, err := tcp.New(srv.Addr())
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), mkQuery(t, "example.com", rrtype.A))
	require.NoError(t, err)
	require.Equal(t, 1, len(resp.Answers()))
	require.Equal(t, "203.0.113.88", resp.Answers()[0].RData().(rdata.A).Addr().String())
}

func TestTCPServerShutdown(t *testing.T) {
	t.Parallel()
	srv, err := dnsserver.ListenTCP(netip.MustParseAddrPort("127.0.0.1:0"),
		dnsserver.HandlerFunc(func(_ context.Context, _ dnsserver.ResponseWriter, _ wire.Message) {}))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()

	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, dnsserver.ErrServerClosed)
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return")
	}
}

func TestTCPServerNoTruncation(t *testing.T) {
	t.Parallel()

	h := dnsserver.HandlerFunc(func(_ context.Context, w dnsserver.ResponseWriter, q wire.Message) {
		b := wire.NewBuilder().
			ID(q.ID()).
			Response(true).
			Question(q.Questions()[0])
		long := make([]byte, 200)
		for i := range long {
			long[i] = 'X'
		}
		txt, _ := rdata.NewTXT(string(long))
		for i := 0; i < 50; i++ {
			b = b.Answer(wire.NewRecord(q.Questions()[0].Name(), time.Minute, txt))
		}
		resp, _ := b.Build()
		_ = w.WriteMsg(resp)
	})
	srv := startTCP(t, h)

	ex, err := tcp.New(srv.Addr())
	require.NoError(t, err)

	q, _ := wire.NewBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.TXT)).
		Build()
	resp, err := ex.Exchange(t.Context(), q)
	require.NoError(t, err)
	require.False(t, resp.Flags().Truncated())
	require.Equal(t, 50, len(resp.Answers()))
}
