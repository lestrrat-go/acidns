package acidns_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

func startUDP(t *testing.T, h acidns.Handler) (*acidns.UDPController, context.CancelFunc) {
	t.Helper()
	srv, err := acidns.NewUDPServer(netip.MustParseAddrPort("127.0.0.1:0"), h)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)
	require.NoError(t, err)
	return ctrl, cancel
}

func mkQuery(t *testing.T, name string, rt rrtype.Type) wire.Message {
	t.Helper()
	q, err := wire.NewBuilder().
		ID(0x1234).
		RecursionDesired(true).
		Question(wire.NewQuestion(wire.MustParseName(name), rt)).
		Build()
	require.NoError(t, err)
	return q
}

func TestUDPServerEcho(t *testing.T) {
	t.Parallel()

	h := acidns.HandlerFunc(func(_ context.Context, w acidns.ResponseWriter, q wire.Message) {
		ans := wire.NewRecord(q.Questions()[0].Name(), time.Minute,
			rdata.MustNewA(netip.MustParseAddr("203.0.113.77")))
		resp, _ := wire.NewBuilder().
			ID(q.ID()).
			Response(true).
			RecursionAvailable(true).
			Question(q.Questions()[0]).
			Answer(ans).
			Build()
		_ = w.WriteMsg(resp)
	})
	ctrl, _ := startUDP(t, h)

	ex, err := acidns.NewUDPExchanger(ctrl.Addr())
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), mkQuery(t, "example.com", rrtype.A))
	require.NoError(t, err)
	require.Equal(t, 1, len(resp.Answers()))
	require.Equal(t, "203.0.113.77", resp.Answers()[0].RData().(rdata.A).Addr().String())
}

func TestUDPServerShutdownOnContextCancel(t *testing.T) {
	t.Parallel()

	h := acidns.HandlerFunc(func(_ context.Context, _ acidns.ResponseWriter, _ wire.Message) {})
	srv, err := acidns.NewUDPServer(netip.MustParseAddrPort("127.0.0.1:0"), h)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	ctrl, err := srv.Run(ctx)
	require.NoError(t, err)

	cancel()
	select {
	case <-ctrl.Done():
		require.NoError(t, ctrl.Err())
	case <-time.After(2 * time.Second):
		t.Fatal("server did not exit after ctx cancel")
	}
}

func TestUDPServerTruncation(t *testing.T) {
	t.Parallel()

	// Build a response so large it can't fit in the default 512-byte UDP
	// limit: 50 long TXT records.
	h := acidns.HandlerFunc(func(_ context.Context, w acidns.ResponseWriter, q wire.Message) {
		b := wire.NewBuilder().
			ID(q.ID()).
			Response(true).
			Question(q.Questions()[0])
		long := make([]byte, 200)
		for i := range long {
			long[i] = 'A'
		}
		txt, _ := rdata.NewTXT(string(long))
		for range 50 {
			b = b.Answer(wire.NewRecord(q.Questions()[0].Name(), time.Minute, txt))
		}
		resp, _ := b.Build()
		_ = w.WriteMsg(resp)
	})
	ctrl, _ := startUDP(t, h)

	ex, err := acidns.NewUDPExchanger(ctrl.Addr())
	require.NoError(t, err)

	// Send a query WITHOUT EDNS so the server caps at 512 bytes.
	q, err := wire.NewBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.TXT)).
		Build()
	require.NoError(t, err)

	resp, err := ex.Exchange(t.Context(), q)
	require.NoError(t, err)
	require.True(t, resp.Flags().Truncated(), "TC bit should be set")
	require.Equal(t, 0, len(resp.Answers()), "answers should be stripped on truncation")
}

func TestUDPServerEDNSPayloadSize(t *testing.T) {
	t.Parallel()

	h := acidns.HandlerFunc(func(_ context.Context, w acidns.ResponseWriter, q wire.Message) {
		b := wire.NewBuilder().
			ID(q.ID()).
			Response(true).
			Question(q.Questions()[0])
		// 10 short TXT records — fits in 4096 but not 512
		short, _ := rdata.NewTXT("hello")
		for range 10 {
			b = b.Answer(wire.NewRecord(q.Questions()[0].Name(), time.Minute, short))
		}
		// pad with more TXT to push past 512 bytes
		long := make([]byte, 100)
		for i := range long {
			long[i] = 'B'
		}
		txt, _ := rdata.NewTXT(string(long))
		for range 5 {
			b = b.Answer(wire.NewRecord(q.Questions()[0].Name(), time.Minute, txt))
		}
		resp, _ := b.Build()
		_ = w.WriteMsg(resp)
	})
	ctrl, _ := startUDP(t, h)

	ex, err := acidns.NewUDPExchanger(ctrl.Addr())
	require.NoError(t, err)

	// Query with EDNS advertising 4096 bytes — server should not truncate.
	q, err := wire.NewBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.TXT)).
		EDNS(mustEDNS(t, wire.NewEDNSBuilder().UDPSize(4096))).
		Build()
	require.NoError(t, err)

	resp, err := ex.Exchange(t.Context(), q)
	require.NoError(t, err)
	require.False(t, resp.Flags().Truncated(), "TC bit should NOT be set with EDNS 4096")
	require.Equal(t, 15, len(resp.Answers()))
}
