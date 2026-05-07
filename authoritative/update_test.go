package authoritative_test

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/authoritative"
	"github.com/lestrrat-go/acidns/update"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/zonefile"
	"github.com/stretchr/testify/require"
)

const updateZone = `$ORIGIN example.com.
$TTL 60
@   IN  SOA  ns1.example.com. hm.example.com. ( 1 2 3 4 5 )
@   IN  NS   ns1.example.com.
ns1 IN  A    192.0.2.10
www IN  A    192.0.2.42
`

func startUpdatable(t *testing.T) (authoritative.Authoritative, netip.AddrPort) {
	t.Helper()
	z, err := zonefile.Parse(strings.NewReader(updateZone))
	require.NoError(t, err)
	a, err := authoritative.New(authoritative.WithZone(z))
	require.NoError(t, err)
	srv, err := acidns.ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"), a)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx) }()
	return a, srv.Addr()
}

func TestUpdateAddRRset(t *testing.T) {
	t.Parallel()
	a, addr := startUpdatable(t)

	// Add new record at "blog.example.com".
	new := wire.NewRecord(wire.MustParseName("blog.example.com"), 60*time.Second,
		rdata.NewA(netip.MustParseAddr("198.51.100.5")))

	ex, err := acidns.NewUDPExchanger(addr)
	require.NoError(t, err)
	msg, err := update.NewBuilder(wire.MustParseName("example.com")).
		AddRRset(new).
		Build()
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), msg)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())

	// Verify the new record appears in subsequent queries.
	q, _ := wire.NewBuilder().
		ID(2).
		Question(wire.NewQuestion(wire.MustParseName("blog.example.com"), rrtype.A)).
		Build()
	r2, err := ex.Exchange(t.Context(), q)
	require.NoError(t, err)
	require.Equal(t, 1, len(r2.Answers()))
	require.Equal(t, "198.51.100.5", r2.Answers()[0].RData().(rdata.A).Addr().String())
	_ = a
}

func TestUpdateDeleteRRset(t *testing.T) {
	t.Parallel()
	_, addr := startUpdatable(t)

	ex, err := acidns.NewUDPExchanger(addr)
	require.NoError(t, err)
	msg, err := update.NewBuilder(wire.MustParseName("example.com")).
		DeleteRRset(wire.MustParseName("www.example.com"), rrtype.A).
		Build()
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), msg)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())

	// Now www.example.com should NXDOMAIN (we don't keep namesExist after delete) or NODATA.
	q, _ := wire.NewBuilder().
		ID(3).
		Question(wire.NewQuestion(wire.MustParseName("www.example.com"), rrtype.A)).
		Build()
	r, err := ex.Exchange(t.Context(), q)
	require.NoError(t, err)
	require.Equal(t, 0, len(r.Answers()))
}

func TestUpdatePrereqRRsetExistsFails(t *testing.T) {
	t.Parallel()
	_, addr := startUpdatable(t)

	ex, err := acidns.NewUDPExchanger(addr)
	require.NoError(t, err)
	msg, err := update.NewBuilder(wire.MustParseName("example.com")).
		PrereqRRsetExists(wire.MustParseName("nope.example.com"), rrtype.A).
		AddRRset(wire.NewRecord(wire.MustParseName("blog.example.com"), 60*time.Second,
			rdata.NewA(netip.MustParseAddr("198.51.100.7")))).
		Build()
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), msg)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENXRRSet, resp.Flags().RCODE())
}

func TestUpdatePrereqRRsetAbsentSucceeds(t *testing.T) {
	t.Parallel()
	_, addr := startUpdatable(t)

	ex, err := acidns.NewUDPExchanger(addr)
	require.NoError(t, err)
	msg, err := update.NewBuilder(wire.MustParseName("example.com")).
		PrereqRRsetAbsent(wire.MustParseName("blog.example.com"), rrtype.A).
		AddRRset(wire.NewRecord(wire.MustParseName("blog.example.com"), 60*time.Second,
			rdata.NewA(netip.MustParseAddr("198.51.100.8")))).
		Build()
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), msg)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())
}

func TestUpdateOutOfZoneRefused(t *testing.T) {
	t.Parallel()
	_, addr := startUpdatable(t)
	ex, err := acidns.NewUDPExchanger(addr)
	require.NoError(t, err)
	msg, err := update.NewBuilder(wire.MustParseName("example.org")).
		AddRRset(wire.NewRecord(wire.MustParseName("a.example.org"), 60*time.Second,
			rdata.NewA(netip.MustParseAddr("198.51.100.9")))).
		Build()
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), msg)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENotAuth, resp.Flags().RCODE())
}
