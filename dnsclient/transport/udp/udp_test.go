package udp_test

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient/transport/udp"
	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/stretchr/testify/require"
)

// startEcho spins up a UDP responder that answers every query with a single
// A record pointing at 203.0.113.1. The returned cleanup must be deferred.
func startEcho(t *testing.T) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { pc.Close() })

	go func() {
		buf := make([]byte, 4096)
		for {
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			req, err := dnsmsg.Unmarshal(buf[:n])
			if err != nil {
				continue
			}
			ans := dnsmsg.NewRecord(req.Questions()[0].Name(), 60*time.Second,
				rdata.NewA(netip.MustParseAddr("203.0.113.1")))
			resp, err := dnsmsg.NewBuilder().
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
			wire, err := dnsmsg.Marshal(resp)
			if err != nil {
				continue
			}
			pc.WriteTo(wire, src)
		}
	}()

	a := pc.LocalAddr().(*net.UDPAddr)
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port))
}

func TestExchange(t *testing.T) {
	t.Parallel()
	addr := startEcho(t)

	ex, err := udp.New(addr)
	require.NoError(t, err)

	q, err := dnsmsg.NewBuilder().
		ID(0xbeef).
		RecursionDesired(true).
		Question(dnsmsg.NewQuestion(dnsname.MustParse("example.com"), rrtype.A)).
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
	t.Cleanup(func() { pc.Close() })
	a := pc.LocalAddr().(*net.UDPAddr)
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port))

	ex, err := udp.New(addr)
	require.NoError(t, err)

	q, _ := dnsmsg.NewBuilder().
		ID(1).
		Question(dnsmsg.NewQuestion(dnsname.MustParse("example.com"), rrtype.A)).
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
	t.Cleanup(func() { pc.Close() })
	a := pc.LocalAddr().(*net.UDPAddr)
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port))

	go func() {
		buf := make([]byte, 4096)
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		req, err := dnsmsg.Unmarshal(buf[:n])
		if err != nil {
			return
		}
		// Spoof: respond with a different ID first, then with the correct one.
		bad, _ := dnsmsg.NewBuilder().
			ID(req.ID() ^ 0xffff).
			Response(true).
			Question(req.Questions()[0]).
			Build()
		bw, _ := dnsmsg.Marshal(bad)
		pc.WriteTo(bw, src)

		good, _ := dnsmsg.NewBuilder().
			ID(req.ID()).
			Response(true).
			Question(req.Questions()[0]).
			Answer(dnsmsg.NewRecord(req.Questions()[0].Name(), time.Minute,
				rdata.NewA(netip.MustParseAddr("203.0.113.2")))).
			Build()
		gw, _ := dnsmsg.Marshal(good)
		pc.WriteTo(gw, src)
	}()

	ex, err := udp.New(addr, udp.WithTimeout(2*time.Second))
	require.NoError(t, err)
	q, _ := dnsmsg.NewBuilder().
		ID(0x1234).
		RecursionDesired(true).
		Question(dnsmsg.NewQuestion(dnsname.MustParse("example.com"), rrtype.A)).
		Build()

	resp, err := ex.Exchange(t.Context(), q)
	require.NoError(t, err)
	require.Equal(t, q.ID(), resp.ID())
	require.Equal(t, 1, len(resp.Answers()))
}
