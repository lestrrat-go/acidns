package acidns_test

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/stretchr/testify/require"
)

func TestResolveAs_A(t *testing.T) {
	t.Parallel()
	addr := startServer(t,
		[]netip.Addr{netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2")},
		nil,
	)
	r := newResolver(t, addr)

	as, err := acidns.ResolveAs[rdata.A](t.Context(), r, wire.MustParseName("example.com"))
	require.NoError(t, err)
	got := make([]string, len(as))
	for i, a := range as {
		got[i] = a.Addr().String()
	}
	slices.Sort(got)
	require.Equal(t, []string{"203.0.113.1", "203.0.113.2"}, got)
}

// Extract[rdata.RData] is the degenerate "any rdata" form. The umbrella
// interface has no inherent rrtype, so the type filter is skipped and
// every record is returned. Earlier code would panic at Type() on the
// nil interface zero value.
func TestExtract_UmbrellaInterface(t *testing.T) {
	t.Parallel()
	a, err := rdata.NewA(netip.MustParseAddr("203.0.113.1"))
	require.NoError(t, err)
	aaaa, err := rdata.NewAAAA(netip.MustParseAddr("2001:db8::1"))
	require.NoError(t, err)
	recs := []wire.Record{
		wire.NewRecord(wire.MustParseName("example.com"), 60*time.Second, a),
		wire.NewRecord(wire.MustParseName("example.com"), 60*time.Second, aaaa),
	}

	got := acidns.Extract[rdata.RData](recs)
	require.Len(t, got, 2)
}

// ResolveAs[rdata.AAAA] against an A-only zone returns zero results — the
// owner-type filter (inferred from T's zero value) excludes A records.
func TestResolveAs_TypeFilterPreventsCollision(t *testing.T) {
	t.Parallel()
	addr := startServer(t,
		[]netip.Addr{netip.MustParseAddr("203.0.113.1")},
		nil,
	)
	r := newResolver(t, addr)

	as, err := acidns.ResolveAs[rdata.AAAA](t.Context(), r, wire.MustParseName("example.com"))
	require.NoError(t, err)
	require.Empty(t, as) // server returns no AAAA records
}
