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

// startEcho spins up a UDP responder that answers every query with a single
// A record pointing at 203.0.113.1. The returned cleanup must be deferred.
func startEcho(t *testing.T) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })

	go func() {
		buf := make([]byte, 4096)
		for {
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			req, err := wire.Unpack(buf[:n])
			if err != nil {
				continue
			}
			ar, err := rdata.NewA(netip.MustParseAddr("203.0.113.1"))
			require.NoError(t, err)
			ans := wire.NewRecord(req.Questions()[0].Name(), 60*time.Second,
				ar)
			resp, err := wire.NewMessageBuilder().
				ID(req.ID()).
				Response(true).
				RecursionDesired(req.Flags().RecursionDesired()).
				RecursionAvailable(true).
				Question(req.Questions()[0]).
				Answer(ans).
				Build()
			if err != nil {
				continue
			}
			wire, err := wire.Pack(resp)
			if err != nil {
				continue
			}
			_, _ = pc.WriteTo(wire, src)
		}
	}()

	a := pc.LocalAddr().(*net.UDPAddr)
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port))
}

func TestExchange(t *testing.T) {
	t.Parallel()
	addr := startEcho(t)

	ex, err := acidns.NewUDPClient(addr)
	require.NoError(t, err)

	q, err := wire.NewMessageBuilder().
		ID(0xbeef).
		RecursionDesired(true).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	require.NoError(t, err)

	resp, err := ex.Exchange(t.Context(), q)
	require.NoError(t, err)
	require.Equal(t, q.ID(), resp.ID())
	require.True(t, resp.Flags().Response())
	require.Equal(t, 1, len(resp.Answers()))

	a, ok := resp.Answers()[0].RData().(rdata.A)
	require.True(t, ok)
	require.Equal(t, "203.0.113.1", a.Addr().String())
}

func TestExchangeContextCancelled(t *testing.T) {
	t.Parallel()

	// Bind a port but never respond — exchange must return when ctx fires.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	a := pc.LocalAddr().(*net.UDPAddr)
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port))

	ex, err := acidns.NewUDPClient(addr)
	require.NoError(t, err)

	q, _ := wire.NewMessageBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	_, err = ex.Exchange(ctx, q)
	require.Error(t, err)
}

func TestExchangeMismatchedID(t *testing.T) {
	t.Parallel()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	a := pc.LocalAddr().(*net.UDPAddr)
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port))

	go func() {
		buf := make([]byte, 4096)
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		req, err := wire.Unpack(buf[:n])
		if err != nil {
			return
		}
		// Spoof: respond with a different ID first, then with the correct one.
		bad, _ := wire.NewMessageBuilder().
			ID(req.ID() ^ 0xffff).
			Response(true).
			Question(req.Questions()[0]).
			Build()
		bw, _ := wire.Pack(bad)
		_, _ = pc.WriteTo(bw, src)

		ar2, err := rdata.NewA(netip.MustParseAddr("203.0.113.2"))
		require.NoError(t, err)
		good, _ := wire.NewMessageBuilder().
			ID(req.ID()).
			Response(true).
			Question(req.Questions()[0]).
			Answer(wire.NewRecord(req.Questions()[0].Name(), time.Minute,
				ar2)).
			Build()
		gw, _ := wire.Pack(good)
		_, _ = pc.WriteTo(gw, src)
	}()

	ex, err := acidns.NewUDPClient(addr, acidns.WithUDPClientTimeout(2*time.Second))
	require.NoError(t, err)
	q, _ := wire.NewMessageBuilder().
		ID(0x1234).
		RecursionDesired(true).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()

	resp, err := ex.Exchange(t.Context(), q)
	require.NoError(t, err)
	require.Equal(t, q.ID(), resp.ID())
	require.Equal(t, 1, len(resp.Answers()))
}
