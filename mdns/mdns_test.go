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
	srv := rdata.MustNewSRV(0, 0, 80, host)
	a := rdata.MustNewA(netip.MustParseAddr("192.0.2.50"))

	resp, err := wire.NewMessageBuilder().
		ID(0).
		Response(true).
		Answer(wire.NewRecord(svcType, time.Minute, rdata.MustNewPTR(instance))).
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
