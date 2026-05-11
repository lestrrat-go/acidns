package mdns_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/mdns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

func TestBuildBrowseQuery(t *testing.T) {
	t.Parallel()

	q, err := mdns.BuildBrowseQuery("_http._tcp")
	require.NoError(t, err)
	require.Equal(t, uint16(0), q.ID())
	require.Equal(t, 1, len(q.Questions()))
	require.Equal(t, "_http._tcp.local.", q.Questions()[0].Name().String())
	require.Equal(t, rrtype.PTR, q.Questions()[0].Type())
}

func TestParseBrowseResponse(t *testing.T) {
	t.Parallel()

	svcType := wire.MustParseName("_http._tcp.local")
	instance := wire.MustParseName("My Printer._http._tcp.local")
	host := wire.MustParseName("printer.local")

	txt, _ := rdata.NewTXT("path=/admin", "model=acidns-bench")
	srv, err := rdata.NewSRV(0, 0, 80, host)
	require.NoError(t, err)
	a, err := rdata.NewA(netip.MustParseAddr("192.0.2.50"))
	require.NoError(t, err)

	ptr, err := rdata.NewPTR(instance)
	require.NoError(t, err)
	resp, err := wire.NewMessageBuilder().
		ID(0).
		Response(true).
		Answer(wire.NewRecord(svcType, time.Minute, ptr)).
		Answer(wire.NewRecord(instance, time.Minute, srv)).
		Answer(wire.NewRecord(instance, time.Minute, txt)).
		Additional(wire.NewRecord(host, time.Minute, a)).
		Build()
	require.NoError(t, err)

	services := mdns.ParseBrowseResponse(resp)
	require.Equal(t, 1, len(services))

	s := services[0]
	// dnsname canonicalises owner labels to lowercase; the parsed
	// instance name reflects that. Real mDNS responders should send
	// case-preserving instance labels via escapes if case matters.
	require.Equal(t, "my printer", s.Instance())
	require.Equal(t, "_http._tcp.local.", s.Type().String())
	require.Equal(t, "printer.local.", s.Host().String())
	require.Equal(t, uint16(80), s.Port())
	require.Equal(t, "192.0.2.50", s.Addrs()[0].String())
	require.Equal(t, "/admin", s.Text()["path"])
	require.Equal(t, "acidns-bench", s.Text()["model"])
}

func TestParseBrowseResponseEmpty(t *testing.T) {
	t.Parallel()
	resp, _ := wire.NewMessageBuilder().ID(0).Response(true).Build()
	require.Equal(t, 0, len(mdns.ParseBrowseResponse(resp)))
}

func TestServiceNameNormalisation(t *testing.T) {
	t.Parallel()
	for _, in := range []string{"_http._tcp", "_http._tcp.local", "_http._tcp.local."} {
		q, err := mdns.BuildBrowseQuery(in)
		require.NoError(t, err)
		require.Equal(t, "_http._tcp.local.", q.Questions()[0].Name().String())
	}
}

// TestServiceBuilderSingleShot verifies that ServiceBuilder.Build
// resets the builder so a second Build does not leak the first
// Service's slice/map fields.
func TestServiceBuilderSingleShot(t *testing.T) {
	t.Parallel()
	b := mdns.NewServiceBuilder().
		Instance("printer").
		Type(wire.MustParseName("_http._tcp.local.")).
		Host(wire.MustParseName("printer.local.")).
		Port(80).
		Addrs([]netip.Addr{netip.MustParseAddr("192.0.2.1")}).
		Text(map[string]string{"k": "v"}).
		TTL(120 * time.Second)

	first := b.Build()
	require.Equal(t, "printer", first.Instance())
	require.Equal(t, uint16(80), first.Port())
	require.Len(t, first.Addrs(), 1)
	require.Equal(t, "v", first.Text()["k"])

	// Builder reset — second Build is the zero Service.
	second := b.Build()
	require.Equal(t, "", second.Instance())
	require.Equal(t, uint16(0), second.Port())
	require.Empty(t, second.Addrs())
	require.Empty(t, second.Text())

	// First Service is unaffected.
	require.Equal(t, "printer", first.Instance())
}
