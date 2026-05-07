package authoritative_test

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/lestrrat-go/acidns/dnsclient/transport/tcp"
	"github.com/lestrrat-go/acidns/dnsserver"
	"github.com/lestrrat-go/acidns/authoritative"
	"github.com/lestrrat-go/acidns/dnszone"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

func TestAXFRRefusedOverUDP(t *testing.T) {
	t.Parallel()
	a := newAuth(t)
	q, _ := wire.NewBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.AXFR)).
		Build()
	w := &inProcWriter{network: "udp"}
	a.ServeDNS(context.Background(), w, q)
	require.Equal(t, wire.RCODERefused, w.resp.Flags().RCODE())
}

func TestAXFRNotAuthForOtherZone(t *testing.T) {
	t.Parallel()
	a := newAuth(t)
	q, _ := wire.NewBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("example.org"), rrtype.AXFR)).
		Build()
	w := &inProcWriter{network: "tcp"}
	a.ServeDNS(context.Background(), w, q)
	// Outside any of our zones — REFUSED via the normal lookup path.
	require.Equal(t, wire.RCODERefused, w.resp.Flags().RCODE())
}

func TestAXFROverTCP(t *testing.T) {
	t.Parallel()

	z, err := dnszone.Parse(strings.NewReader(sampleZone))
	require.NoError(t, err)
	h, err := authoritative.New(authoritative.WithZone(z))
	require.NoError(t, err)

	srv, err := dnsserver.ListenTCP(netip.MustParseAddrPort("127.0.0.1:0"), h)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx) }()

	ex, err := tcp.New(srv.Addr())
	require.NoError(t, err)

	q, _ := wire.NewBuilder().
		ID(0xa1f1).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.AXFR)).
		Build()
	resp, err := ex.Exchange(t.Context(), q)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())
	require.True(t, resp.Flags().Authoritative())

	// First and last answers must be SOA; everything else is the rest.
	ans := resp.Answers()
	require.GreaterOrEqual(t, len(ans), 3)
	require.Equal(t, rrtype.SOA, ans[0].Type())
	require.Equal(t, rrtype.SOA, ans[len(ans)-1].Type())

	// Sample zone has 9 non-SOA records, so total should be 11.
	soaCount := 0
	for _, r := range ans {
		if r.Type() == rrtype.SOA {
			soaCount++
		}
	}
	require.Equal(t, 2, soaCount)
}
