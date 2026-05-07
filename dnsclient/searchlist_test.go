package dnsclient_test

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/dnsclient"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// startSearchServer spins up a UDP responder that returns 192.0.2.1 for the
// "wanted" name and NXDOMAIN for everything else. It records every QNAME
// it observed so the test can assert on the order names were tried.
func startSearchServer(t *testing.T, wanted string) (netip.AddrPort, func() []string) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { pc.Close() })

	var queriedAtomic atomic.Pointer[[]string]
	queriedAtomic.Store(&[]string{})

	go func() {
		buf := make([]byte, 4096)
		for {
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			req, err := wire.Unmarshal(buf[:n])
			if err != nil || len(req.Questions()) == 0 {
				continue
			}
			q := req.Questions()[0]

			cur := *queriedAtomic.Load()
			cur = append(cur, q.Name().String())
			queriedAtomic.Store(&cur)

			b := wire.NewBuilder().
				ID(req.ID()).
				Response(true).
				RecursionAvailable(true).
				Question(q)
			if q.Name().String() == wanted {
				if q.Type() == rrtype.A {
					b = b.Answer(wire.NewRecord(q.Name(), time.Minute,
						rdata.NewA(netip.MustParseAddr("192.0.2.1"))))
				}
			} else {
				b = b.RCODE(wire.RCODENXDomain)
			}
			resp, _ := b.Build()
			wire, _ := wire.Marshal(resp)
			pc.WriteTo(wire, src)
		}
	}()

	a := pc.LocalAddr().(*net.UDPAddr)
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port))
	queries := func() []string { return *queriedAtomic.Load() }
	return addr, queries
}

func TestSearchListSuffixed(t *testing.T) {
	t.Parallel()

	addr, queries := startSearchServer(t, "host.example.com.")
	ex, _ := acidns.NewUDPExchanger(addr)
	r, err := dnsclient.New(
		dnsclient.WithExchanger(ex),
		dnsclient.WithSearchList(wire.MustParseName("example.com")),
		dnsclient.WithNdots(2),
	)
	require.NoError(t, err)

	addrs, err := dnsclient.LookupHost(t.Context(), r, "host")
	require.NoError(t, err)
	require.Equal(t, 1, len(addrs))
	require.Equal(t, "192.0.2.1", addrs[0].String())

	// Wait briefly for any in-flight queries to be recorded.
	time.Sleep(20 * time.Millisecond)
	q := queries()
	require.Contains(t, q, "host.example.com.")
}

func TestSearchListAbsoluteSkipsSearch(t *testing.T) {
	t.Parallel()

	addr, queries := startSearchServer(t, "host.")
	ex, _ := acidns.NewUDPExchanger(addr)
	r, err := dnsclient.New(
		dnsclient.WithExchanger(ex),
		dnsclient.WithSearchList(wire.MustParseName("example.com")),
		dnsclient.WithNdots(2),
	)
	require.NoError(t, err)

	addrs, err := dnsclient.LookupHost(t.Context(), r, "host.")
	require.NoError(t, err)
	require.Equal(t, 1, len(addrs))

	time.Sleep(20 * time.Millisecond)
	q := queries()
	for _, n := range q {
		require.NotContains(t, n, "example.com.", "absolute name must not be suffixed")
	}
}

func TestSearchListNdotsAbsoluteFirst(t *testing.T) {
	t.Parallel()

	addr, queries := startSearchServer(t, "a.b.c.")
	ex, _ := acidns.NewUDPExchanger(addr)
	r, err := dnsclient.New(
		dnsclient.WithExchanger(ex),
		dnsclient.WithSearchList(wire.MustParseName("example.com")),
		dnsclient.WithNdots(1), // a.b.c has 2 dots ≥ ndots → try absolute first
	)
	require.NoError(t, err)

	addrs, err := dnsclient.LookupHost(t.Context(), r, "a.b.c")
	require.NoError(t, err)
	require.Equal(t, 1, len(addrs))

	time.Sleep(20 * time.Millisecond)
	q := queries()
	// "a.b.c." should appear in the trace BEFORE "a.b.c.example.com." (or
	// the latter shouldn't be queried at all because absolute succeeded).
	posAbs := -1
	posSuf := -1
	for i, name := range q {
		if name == "a.b.c." && posAbs < 0 {
			posAbs = i
		}
		if name == "a.b.c.example.com." && posSuf < 0 {
			posSuf = i
		}
	}
	require.GreaterOrEqual(t, posAbs, 0)
	if posSuf >= 0 {
		require.Less(t, posAbs, posSuf)
	}
}

func TestSearchListUnused(t *testing.T) {
	t.Parallel()
	// No search list configured → behave exactly as before.
	addr, _ := startSearchServer(t, "host.")
	ex, _ := acidns.NewUDPExchanger(addr)
	r, err := dnsclient.New(dnsclient.WithExchanger(ex))
	require.NoError(t, err)

	_, err = dnsclient.LookupHost(context.WithValue(t.Context(), struct{}{}, 1), r, "host.")
	require.NoError(t, err)
}
