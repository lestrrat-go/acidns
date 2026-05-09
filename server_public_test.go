package acidns_test

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

func publicMkInner() acidns.Handler {
	return acidns.HandlerFunc(func(_ context.Context, w acidns.ResponseWriter, q wire.Message) {
		ans := wire.NewRecord(q.Questions()[0].Name(), time.Minute,
			rdata.MustNewA(netip.MustParseAddr("203.0.113.42")))
		resp, _ := wire.NewMessageBuilder().
			ID(q.ID()).
			Response(true).
			RecursionAvailable(true).
			Question(q.Questions()[0]).
			Answer(ans).
			Build()
		_ = w.WriteMsg(resp)
	})
}

func TestNewPublicUDPServer_RequiresAllowList(t *testing.T) {
	t.Parallel()

	_, err := acidns.NewPublicUDPServer(
		netip.MustParseAddrPort("127.0.0.1:0"),
		publicMkInner(),
	)
	require.ErrorIs(t, err, acidns.ErrPublicACLRequired)
}

func TestNewPublicTCPServer_RequiresAllowList(t *testing.T) {
	t.Parallel()

	_, err := acidns.NewPublicTCPServer(
		netip.MustParseAddrPort("127.0.0.1:0"),
		publicMkInner(),
	)
	require.ErrorIs(t, err, acidns.ErrPublicACLRequired)
}

func TestNewPublicUDPServer_HappyPath(t *testing.T) {
	t.Parallel()

	srv, err := acidns.NewPublicUDPServer(
		netip.MustParseAddrPort("127.0.0.1:0"),
		publicMkInner(),
		acidns.WithPublicACLOptions(
			acidns.WithACLAllow(netip.MustParsePrefix("127.0.0.0/8")),
		),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)
	require.NoError(t, err)

	// Allowed source: full round trip works.
	ex, err := acidns.NewUDPExchanger(ctrl.Addr())
	require.NoError(t, err)
	q, err := wire.NewMessageBuilder().
		ID(0x4242).
		RecursionDesired(true).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), q)
	require.NoError(t, err)
	require.Equal(t, 1, len(resp.Answers()))
	require.Equal(t, "203.0.113.42", resp.Answers()[0].RData().(rdata.A).Addr().String())
}

func TestNewPublicUDPServer_DropsDeniedSilently(t *testing.T) {
	t.Parallel()

	// Allow only an unreachable prefix so the loopback exchange we make
	// is treated as denied. WithACLDropDenied(true) is baked into the
	// public stack, so the denied query receives no reply at all.
	srv, err := acidns.NewPublicUDPServer(
		netip.MustParseAddrPort("127.0.0.1:0"),
		publicMkInner(),
		acidns.WithPublicACLOptions(
			acidns.WithACLAllow(netip.MustParsePrefix("198.51.100.0/24")),
		),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)
	require.NoError(t, err)

	// Send a raw UDP packet from loopback (which is NOT in 198.51.100.0/24)
	// and confirm we get no reply within a short timeout.
	conn, err := net.Dial("udp", ctrl.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	q, err := wire.NewMessageBuilder().
		ID(0x9999).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	require.NoError(t, err)
	buf, err := wire.Marshal(q)
	require.NoError(t, err)
	_, err = conn.Write(buf)
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(250*time.Millisecond)))
	rbuf := make([]byte, 4096)
	_, err = conn.Read(rbuf)
	require.Error(t, err, "denied source must receive no reply")
}
