package dnsserver_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient/transport/udp"
	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/lestrrat-go/acidns/dnsserver"
	"github.com/stretchr/testify/require"
)

func startUDP(t *testing.T, h dnsserver.Handler) (dnsserver.Server, context.CancelFunc) {
	t.Helper()
	srv, err := dnsserver.ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"), h)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	go func() { _ = srv.Serve(ctx) }()
	t.Cleanup(cancel)
	return srv, cancel
}

func mkQuery(t *testing.T, name string, rt rrtype.Type) dnsmsg.Message {
	t.Helper()
	q, err := dnsmsg.NewBuilder().
		ID(0x1234).
		RecursionDesired(true).
		Question(dnsmsg.NewQuestion(dnsname.MustParse(name), rt)).
		Build()
	require.NoError(t, err)
	return q
}

func TestUDPServerEcho(t *testing.T) {
	t.Parallel()

	h := dnsserver.HandlerFunc(func(ctx context.Context, w dnsserver.ResponseWriter, q dnsmsg.Message) {
		ans := dnsmsg.NewRecord(q.Questions()[0].Name(), time.Minute,
			rdata.NewA(netip.MustParseAddr("203.0.113.77")))
		resp, _ := dnsmsg.NewBuilder().
			ID(q.ID()).
			Response(true).
			RecursionAvailable(true).
			Question(q.Questions()[0]).
			Answer(ans).
			Build()
		_ = w.WriteMsg(resp)
	})
	srv, _ := startUDP(t, h)

	ex, err := udp.New(srv.Addr())
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), mkQuery(t, "example.com", rrtype.A))
	require.NoError(t, err)
	require.Equal(t, 1, len(resp.Answers()))
	require.Equal(t, "203.0.113.77", resp.Answers()[0].RData().(rdata.A).Addr().String())
}

func TestUDPServerShutdownOnContextCancel(t *testing.T) {
	t.Parallel()

	h := dnsserver.HandlerFunc(func(_ context.Context, _ dnsserver.ResponseWriter, _ dnsmsg.Message) {})
	srv, err := dnsserver.ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"), h)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()

	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, dnsserver.ErrServerClosed)
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after ctx cancel")
	}
}

func TestUDPServerTruncation(t *testing.T) {
	t.Parallel()

	// Build a response so large it can't fit in the default 512-byte UDP
	// limit: 50 long TXT records.
	h := dnsserver.HandlerFunc(func(ctx context.Context, w dnsserver.ResponseWriter, q dnsmsg.Message) {
		b := dnsmsg.NewBuilder().
			ID(q.ID()).
			Response(true).
			Question(q.Questions()[0])
		long := make([]byte, 200)
		for i := range long {
			long[i] = 'A'
		}
		txt, _ := rdata.NewTXT(string(long))
		for i := 0; i < 50; i++ {
			b = b.Answer(dnsmsg.NewRecord(q.Questions()[0].Name(), time.Minute, txt))
		}
		resp, _ := b.Build()
		_ = w.WriteMsg(resp)
	})
	srv, _ := startUDP(t, h)

	ex, err := udp.New(srv.Addr())
	require.NoError(t, err)

	// Send a query WITHOUT EDNS so the server caps at 512 bytes.
	q, err := dnsmsg.NewBuilder().
		ID(1).
		Question(dnsmsg.NewQuestion(dnsname.MustParse("example.com"), rrtype.TXT)).
		Build()
	require.NoError(t, err)

	resp, err := ex.Exchange(t.Context(), q)
	require.NoError(t, err)
	require.True(t, resp.Flags().Truncated(), "TC bit should be set")
	require.Equal(t, 0, len(resp.Answers()), "answers should be stripped on truncation")
}

func TestUDPServerEDNSPayloadSize(t *testing.T) {
	t.Parallel()

	h := dnsserver.HandlerFunc(func(ctx context.Context, w dnsserver.ResponseWriter, q dnsmsg.Message) {
		b := dnsmsg.NewBuilder().
			ID(q.ID()).
			Response(true).
			Question(q.Questions()[0])
		// 10 short TXT records — fits in 4096 but not 512
		short, _ := rdata.NewTXT("hello")
		for i := 0; i < 10; i++ {
			b = b.Answer(dnsmsg.NewRecord(q.Questions()[0].Name(), time.Minute, short))
		}
		// pad with more TXT to push past 512 bytes
		long := make([]byte, 100)
		for i := range long {
			long[i] = 'B'
		}
		txt, _ := rdata.NewTXT(string(long))
		for i := 0; i < 5; i++ {
			b = b.Answer(dnsmsg.NewRecord(q.Questions()[0].Name(), time.Minute, txt))
		}
		resp, _ := b.Build()
		_ = w.WriteMsg(resp)
	})
	srv, _ := startUDP(t, h)

	ex, err := udp.New(srv.Addr())
	require.NoError(t, err)

	// Query with EDNS advertising 4096 bytes — server should not truncate.
	q, err := dnsmsg.NewBuilder().
		ID(1).
		Question(dnsmsg.NewQuestion(dnsname.MustParse("example.com"), rrtype.TXT)).
		EDNS(dnsmsg.NewEDNSBuilder().UDPSize(4096).Build()).
		Build()
	require.NoError(t, err)

	resp, err := ex.Exchange(t.Context(), q)
	require.NoError(t, err)
	require.False(t, resp.Flags().Truncated(), "TC bit should NOT be set with EDNS 4096")
	require.Equal(t, 15, len(resp.Answers()))
}
