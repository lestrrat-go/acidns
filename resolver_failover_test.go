package acidns_test

import (
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/stretchr/testify/require"
)

// peerHandler describes one mock upstream: either a specific RCODE, or a
// NoError response carrying the supplied A address. Used by
// startFailoverPeers to spin up N independent UDP "servers" with a
// per-peer query counter so tests can confirm which peers the failover
// chain actually contacted.
type peerHandler struct {
	rcode wire.RCODE // RCODENoError → return aRecord; anything else → bare RCODE
	a     netip.Addr // populated only when rcode == RCODENoError
}

// startFailoverPeers boots one UDP socket per handler and returns the
// addresses plus a snapshot helper that reports per-peer query counts.
func startFailoverPeers(t *testing.T, handlers []peerHandler) ([]netip.AddrPort, func() []int) {
	t.Helper()
	addrs := make([]netip.AddrPort, len(handlers))
	counts := make([]atomic.Int64, len(handlers))

	for i, h := range handlers {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = pc.Close() })

		ua := pc.LocalAddr().(*net.UDPAddr)
		addrs[i] = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(ua.Port))

		go func(pc net.PacketConn, idx int, h peerHandler) {
			buf := make([]byte, 4096)
			for {
				n, src, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				counts[idx].Add(1)
				req, err := wire.Unpack(buf[:n])
				if err != nil || len(req.Questions()) == 0 {
					continue
				}
				q0 := req.Questions()[0]
				b := wire.NewMessageBuilder().
					ID(req.ID()).
					Response(true).
					RecursionAvailable(true).
					Question(q0)
				if h.rcode != wire.RCODENoError {
					b = b.RCODE(h.rcode)
				} else if h.a.IsValid() {
					ar, _ := rdata.NewA(h.a)
					b = b.Answer(wire.NewRecord(q0.Name(), time.Minute, ar))
				}
				resp, err := b.Build()
				if err != nil {
					continue
				}
				out, err := wire.Pack(resp)
				if err != nil {
					continue
				}
				_, _ = pc.WriteTo(out, src)
			}
		}(pc, i, h)
	}

	return addrs, func() []int {
		out := make([]int, len(counts))
		for i := range counts {
			out[i] = int(counts[i].Load())
		}
		return out
	}
}

// TestFailoverSkipsServFail confirms a SERVFAIL on peer 0 causes the
// stub Resolver to query peer 1 and return its NoError answer.
func TestFailoverSkipsServFail(t *testing.T) {
	t.Parallel()
	addrs, counts := startFailoverPeers(t, []peerHandler{
		{rcode: wire.RCODEServFail},
		{rcode: wire.RCODENoError, a: netip.MustParseAddr("192.0.2.10")},
	})

	r, err := acidns.NewResolver(acidns.WithServers(addrs...))
	require.NoError(t, err)

	got, err := acidns.LookupA(t.Context(), r, wire.MustParseName("example.com."))
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.10")}, got)

	c := counts()
	require.Equal(t, 1, c[0], "peer 0 (SERVFAIL) should be queried once")
	require.Equal(t, 1, c[1], "peer 1 must be queried after peer 0's SERVFAIL")
}

// TestFailoverSkipsRefused confirms REFUSED on peer 0 also triggers failover.
func TestFailoverSkipsRefused(t *testing.T) {
	t.Parallel()
	addrs, counts := startFailoverPeers(t, []peerHandler{
		{rcode: wire.RCODERefused},
		{rcode: wire.RCODENoError, a: netip.MustParseAddr("192.0.2.20")},
	})

	r, err := acidns.NewResolver(acidns.WithServers(addrs...))
	require.NoError(t, err)

	got, err := acidns.LookupA(t.Context(), r, wire.MustParseName("example.com."))
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.20")}, got)

	c := counts()
	require.Equal(t, 1, c[0])
	require.Equal(t, 1, c[1], "peer 1 must be queried after peer 0's REFUSED")
}

// TestFailoverNXDOMAINTerminates pins NXDOMAIN as authoritative-
// definitive: peer 1 must NOT be queried, and the caller sees the
// NXDOMAIN via the *net.DNSError chain (with the typed *RCodeError
// reachable through Unwrap).
func TestFailoverNXDOMAINTerminates(t *testing.T) {
	t.Parallel()
	addrs, counts := startFailoverPeers(t, []peerHandler{
		{rcode: wire.RCODENXDomain},
		{rcode: wire.RCODENoError, a: netip.MustParseAddr("192.0.2.30")},
	})

	r, err := acidns.NewResolver(acidns.WithServers(addrs...))
	require.NoError(t, err)

	_, err = acidns.LookupA(t.Context(), r, wire.MustParseName("missing.example."))
	require.Error(t, err)

	var dnsErr *net.DNSError
	require.True(t, errors.As(err, &dnsErr))
	require.True(t, dnsErr.IsNotFound, "NXDOMAIN must surface as IsNotFound")
	require.True(t, errors.Is(err, acidns.ErrNXDOMAIN),
		"NXDOMAIN sentinel must remain reachable via the error chain")

	c := counts()
	require.Equal(t, 1, c[0], "peer 0 (NXDOMAIN) must be queried once")
	require.Equal(t, 0, c[1], "peer 1 must NOT be queried — NXDOMAIN is terminal")
}

// TestFailoverAllServFail verifies that when every peer returns
// SERVFAIL the Resolver surfaces the *last* response as a typed
// *RCodeError so the caller sees the actual wire RCODE rather than an
// opaque "all servers failed" error.
func TestFailoverAllServFail(t *testing.T) {
	t.Parallel()
	addrs, counts := startFailoverPeers(t, []peerHandler{
		{rcode: wire.RCODEServFail},
		{rcode: wire.RCODEServFail},
	})

	r, err := acidns.NewResolver(acidns.WithServers(addrs...))
	require.NoError(t, err)

	_, err = acidns.LookupA(t.Context(), r, wire.MustParseName("broken.example."))
	require.Error(t, err)

	var dnsErr *net.DNSError
	require.True(t, errors.As(err, &dnsErr))
	require.True(t, dnsErr.IsTemporary, "SERVFAIL must surface as IsTemporary")
	require.True(t, errors.Is(err, acidns.ErrServFail),
		"ServFail sentinel must remain reachable via the error chain")

	c := counts()
	require.Equal(t, 1, c[0], "peer 0 queried once")
	require.Equal(t, 1, c[1], "peer 1 queried once (failover exhausted)")
}

// Compile-time guard against accidentally widening isRetryableRCODE to
// include NXDOMAIN or NoError — those would silently change the
// failover contract. Documents intent at the public-test boundary.
func TestFailoverTerminalRCODEsNeverFailOver(t *testing.T) {
	t.Parallel()
	for _, rc := range []wire.RCODE{wire.RCODENoError, wire.RCODENXDomain, wire.RCODEFormErr, wire.RCODENotImp} {
		t.Run(rc.String(), func(t *testing.T) {
			t.Parallel()
			addrs, counts := startFailoverPeers(t, []peerHandler{
				{rcode: rc, a: netip.MustParseAddr("192.0.2.99")},
				{rcode: wire.RCODENoError, a: netip.MustParseAddr("192.0.2.42")},
			})

			r, err := acidns.NewResolver(acidns.WithServers(addrs...))
			require.NoError(t, err)
			_, _ = acidns.LookupA(t.Context(), r, wire.MustParseName("test.example."))

			c := counts()
			require.Equal(t, 0, c[1],
				"%s must be terminal: peer 1 must NOT be queried", rc)
		})
	}
}
