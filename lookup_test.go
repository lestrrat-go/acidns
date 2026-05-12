package acidns_test

import (
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

// startTypedServer answers each question type with the records the test
// pre-loaded. Unmatched types return an empty NOERROR response.
func startTypedServer(t *testing.T, answers map[rrtype.Type][]wire.Record) netip.AddrPort {
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
			if err != nil || len(req.Questions()) == 0 {
				continue
			}
			q := req.Questions()[0]
			b := wire.NewMessageBuilder().
				ID(req.ID()).
				Response(true).
				RecursionAvailable(true).
				Question(q)
			for _, rec := range answers[q.Type()] {
				b = b.Answer(rec)
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
	}()
	a := pc.LocalAddr().(*net.UDPAddr)
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port))
}

func newResolverFor(t *testing.T, addr netip.AddrPort, opts ...acidns.ResolverOption) acidns.Resolver {
	t.Helper()
	ex, err := acidns.NewUDPClient(addr)
	require.NoError(t, err)
	full := append([]acidns.ResolverOption{acidns.WithExchanger(ex)}, opts...)
	r, err := acidns.NewResolver(full...)
	require.NoError(t, err)
	return r
}

func TestLookupA(t *testing.T) {
	t.Parallel()
	name := wire.MustParseName("example.com.")
	ar, err := rdata.NewA(netip.MustParseAddr("192.0.2.1"))
	require.NoError(t, err)
	rec := wire.NewRecord(name, time.Minute, ar)
	addr := startTypedServer(t, map[rrtype.Type][]wire.Record{rrtype.A: {rec}})
	r := newResolverFor(t, addr)

	got, err := acidns.LookupA(t.Context(), r, name)
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, got)
}

func TestLookupAAAA(t *testing.T) {
	t.Parallel()
	name := wire.MustParseName("example.com.")
	rd, err := rdata.NewAAAA(netip.MustParseAddr("2001:db8::1"))
	require.NoError(t, err)
	rec := wire.NewRecord(name, time.Minute, rd)
	addr := startTypedServer(t, map[rrtype.Type][]wire.Record{rrtype.AAAA: {rec}})
	r := newResolverFor(t, addr)

	got, err := acidns.LookupAAAA(t.Context(), r, name)
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("2001:db8::1")}, got)
}

func TestLookupMX(t *testing.T) {
	t.Parallel()
	name := wire.MustParseName("example.com.")
	rd1, err := rdata.NewMX(10, wire.MustParseName("mx1.example.com."))
	require.NoError(t, err)
	rd2, err := rdata.NewMX(20, wire.MustParseName("mx2.example.com."))
	require.NoError(t, err)
	addr := startTypedServer(t, map[rrtype.Type][]wire.Record{
		rrtype.MX: {
			wire.NewRecord(name, time.Minute, rd1),
			wire.NewRecord(name, time.Minute, rd2),
		},
	})
	r := newResolverFor(t, addr)

	got, err := acidns.LookupMX(t.Context(), r, name)
	require.NoError(t, err)
	require.Equal(t, 2, len(got))
	require.Equal(t, uint16(10), got[0].Preference)
	require.Equal(t, "mx1.example.com.", got[0].Host.String())
	require.Equal(t, uint16(20), got[1].Preference)
}

func TestLookupTXT(t *testing.T) {
	t.Parallel()
	name := wire.MustParseName("example.com.")
	rd, err := rdata.NewTXT("v=spf1 ", "include:_spf.example.com ~all")
	require.NoError(t, err)
	addr := startTypedServer(t, map[rrtype.Type][]wire.Record{
		rrtype.TXT: {wire.NewRecord(name, time.Minute, rd)},
	})
	r := newResolverFor(t, addr)

	got, err := acidns.LookupTXT(t.Context(), r, name)
	require.NoError(t, err)
	require.Equal(t, []string{"v=spf1 include:_spf.example.com ~all"}, got)
}

func TestLookupSRV(t *testing.T) {
	t.Parallel()
	name := wire.MustParseName("_sip._tcp.example.com.")
	rd, err := rdata.NewSRV(10, 60, 5060, wire.MustParseName("sip.example.com."))
	require.NoError(t, err)
	addr := startTypedServer(t, map[rrtype.Type][]wire.Record{
		rrtype.SRV: {wire.NewRecord(name, time.Minute, rd)},
	})
	r := newResolverFor(t, addr)

	got, err := acidns.LookupSRV(t.Context(), r, name)
	require.NoError(t, err)
	require.Equal(t, 1, len(got))
	require.Equal(t, uint16(10), got[0].Priority)
	require.Equal(t, uint16(60), got[0].Weight)
	require.Equal(t, uint16(5060), got[0].Port)
	require.Equal(t, "sip.example.com.", got[0].Target.String())
}

func TestLookupCNAME(t *testing.T) {
	t.Parallel()
	name := wire.MustParseName("alias.example.com.")
	rd, err := rdata.NewCNAME(wire.MustParseName("canonical.example.com."))
	require.NoError(t, err)
	addr := startTypedServer(t, map[rrtype.Type][]wire.Record{
		rrtype.CNAME: {wire.NewRecord(name, time.Minute, rd)},
	})
	r := newResolverFor(t, addr)

	got, err := acidns.LookupCNAME(t.Context(), r, name)
	require.NoError(t, err)
	require.Equal(t, 1, len(got))
	require.Equal(t, "canonical.example.com.", got[0].String())
}

func TestLookupNS(t *testing.T) {
	t.Parallel()
	name := wire.MustParseName("example.com.")
	rd1, err := rdata.NewNS(wire.MustParseName("ns1.example.com."))
	require.NoError(t, err)
	rd2, err := rdata.NewNS(wire.MustParseName("ns2.example.com."))
	require.NoError(t, err)
	addr := startTypedServer(t, map[rrtype.Type][]wire.Record{
		rrtype.NS: {
			wire.NewRecord(name, time.Minute, rd1),
			wire.NewRecord(name, time.Minute, rd2),
		},
	})
	r := newResolverFor(t, addr)

	got, err := acidns.LookupNS(t.Context(), r, name)
	require.NoError(t, err)
	require.Equal(t, 2, len(got))
	require.Equal(t, "ns1.example.com.", got[0].String())
	require.Equal(t, "ns2.example.com.", got[1].String())
}

func TestLookupPTRv4(t *testing.T) {
	t.Parallel()
	rev := wire.MustParseName("1.0.0.127.in-addr.arpa.")
	rd, err := rdata.NewPTR(wire.MustParseName("host.example.com."))
	require.NoError(t, err)
	addr := startTypedServer(t, map[rrtype.Type][]wire.Record{
		rrtype.PTR: {wire.NewRecord(rev, time.Minute, rd)},
	})
	r := newResolverFor(t, addr)

	got, err := acidns.LookupPTR(t.Context(), r, netip.MustParseAddr("127.0.0.1"))
	require.NoError(t, err)
	require.Equal(t, 1, len(got))
	require.Equal(t, "host.example.com.", got[0].String())
}

func TestLookupPTRv6(t *testing.T) {
	t.Parallel()
	// 2001:db8::1 reversed nibble form
	rev := wire.MustParseName(
		"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.")
	rd, err := rdata.NewPTR(wire.MustParseName("host.example.com."))
	require.NoError(t, err)
	addr := startTypedServer(t, map[rrtype.Type][]wire.Record{
		rrtype.PTR: {wire.NewRecord(rev, time.Minute, rd)},
	})
	r := newResolverFor(t, addr)

	got, err := acidns.LookupPTR(t.Context(), r, netip.MustParseAddr("2001:db8::1"))
	require.NoError(t, err)
	require.Equal(t, 1, len(got))
	require.Equal(t, "host.example.com.", got[0].String())
}

// TestLookupHostSearchListDisabled confirms that WithSearchListExpansion(false)
// suppresses suffix expansion even when a search list is configured. The
// "wpad" disclosure scenario: the short name MUST NOT be appended with
// "corp.example."; only the bare "wpad." is queried.
func TestLookupHostSearchListDisabled(t *testing.T) {
	t.Parallel()
	srvAddr, queries := startSearchServer(t, "unreachable.")
	ex, err := acidns.NewUDPClient(srvAddr)
	require.NoError(t, err)
	r, err := acidns.NewResolver(
		acidns.WithExchanger(ex),
		acidns.WithSearchList(wire.MustParseName("corp.example")),
		acidns.WithNdots(2),
		acidns.WithSearchListExpansion(false),
	)
	require.NoError(t, err)

	// Returns no addresses (server only knows "unreachable.") but the
	// search-list suffix must not be tried.
	_, _ = acidns.LookupHost(t.Context(), r, "wpad")

	time.Sleep(20 * time.Millisecond)
	q := queries()
	for _, n := range q {
		require.NotContains(t, n, "corp.example.",
			"search-list expansion disabled but corp.example suffix queried")
	}
}

func TestLookupHostSearchListExpanderCapability(t *testing.T) {
	t.Parallel()
	r, err := acidns.NewResolver(
		acidns.WithServers(netip.MustParseAddrPort("127.0.0.1:1")),
		acidns.WithSearchListExpansion(false),
	)
	require.NoError(t, err)
	e, ok := r.(acidns.SearchListExpander)
	require.True(t, ok)
	require.False(t, e.SearchListExpansionEnabled())

	r2, err := acidns.NewResolver(
		acidns.WithServers(netip.MustParseAddrPort("127.0.0.1:1")),
	)
	require.NoError(t, err)
	e2, ok := r2.(acidns.SearchListExpander)
	require.True(t, ok)
	require.True(t, e2.SearchListExpansionEnabled())
}
