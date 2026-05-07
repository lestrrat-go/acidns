package dnsclient_test

import (
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient"
	"github.com/lestrrat-go/acidns/dnsclient/transport/udp"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// startServer answers A queries with v4Answer and AAAA queries with v6Answer.
// Other types receive an empty NOERROR response.
func startServer(t *testing.T, v4 []netip.Addr, v6 []netip.Addr) netip.AddrPort {
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
			req, err := wire.Unmarshal(buf[:n])
			if err != nil || len(req.Questions()) == 0 {
				continue
			}
			q := req.Questions()[0]
			b := wire.NewBuilder().
				ID(req.ID()).
				Response(true).
				RecursionDesired(req.Flags().RecursionDesired()).
				RecursionAvailable(true).
				Question(q)
			switch q.Type() {
			case rrtype.A:
				for _, a := range v4 {
					b = b.Answer(wire.NewRecord(q.Name(), 60*time.Second, rdata.NewA(a)))
				}
			case rrtype.AAAA:
				for _, a := range v6 {
					b = b.Answer(wire.NewRecord(q.Name(), 60*time.Second, rdata.NewAAAA(a)))
				}
			}
			resp, err := b.Build()
			if err != nil {
				continue
			}
			wire, err := wire.Marshal(resp)
			if err != nil {
				continue
			}
			pc.WriteTo(wire, src)
		}
	}()
	a := pc.LocalAddr().(*net.UDPAddr)
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port))
}

func newResolver(t *testing.T, addr netip.AddrPort) dnsclient.Resolver {
	t.Helper()
	ex, err := udp.New(addr)
	require.NoError(t, err)
	r, err := dnsclient.New(dnsclient.WithExchanger(ex))
	require.NoError(t, err)
	return r
}

func TestResolve(t *testing.T) {
	t.Parallel()
	addr := startServer(t,
		[]netip.Addr{netip.MustParseAddr("203.0.113.1")},
		nil,
	)
	r := newResolver(t, addr)

	ans, err := r.Resolve(t.Context(), wire.MustParseName("example.com"), rrtype.A)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENoError, ans.RCODE())
	require.Equal(t, 1, len(ans.Records()))

	a, ok := ans.Records()[0].RData().(rdata.A)
	require.True(t, ok)
	require.Equal(t, "203.0.113.1", a.Addr().String())
}

func TestLookupHost(t *testing.T) {
	t.Parallel()
	addr := startServer(t,
		[]netip.Addr{netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2")},
		[]netip.Addr{netip.MustParseAddr("2001:db8::1")},
	)
	r := newResolver(t, addr)

	addrs, err := dnsclient.LookupHost(t.Context(), r, "example.com")
	require.NoError(t, err)
	require.Equal(t, 3, len(addrs))

	got := make([]string, len(addrs))
	for i, a := range addrs {
		got[i] = a.String()
	}
	slices.Sort(got)
	require.Equal(t, []string{"2001:db8::1", "203.0.113.1", "203.0.113.2"}, got)
}

func TestLookupHostV4Only(t *testing.T) {
	t.Parallel()
	addr := startServer(t,
		[]netip.Addr{netip.MustParseAddr("203.0.113.1")},
		nil,
	)
	r := newResolver(t, addr)

	addrs, err := dnsclient.LookupHost(t.Context(), r, "example.com")
	require.NoError(t, err)
	require.Equal(t, 1, len(addrs))
	require.Equal(t, "203.0.113.1", addrs[0].String())
}

func TestNewRequiresExchangerOrServers(t *testing.T) {
	t.Parallel()
	_, err := dnsclient.New()
	require.Error(t, err)
}

func TestNewWithServers(t *testing.T) {
	t.Parallel()
	addr := startServer(t, []netip.Addr{netip.MustParseAddr("203.0.113.1")}, nil)
	r, err := dnsclient.New(dnsclient.WithServers(addr))
	require.NoError(t, err)
	addrs, err := dnsclient.LookupHost(t.Context(), r, "example.com")
	require.NoError(t, err)
	require.Equal(t, 1, len(addrs))
}
