package dnsclient_test

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/lestrrat-go/acidns/dnsclient"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

func TestResolveAs_A(t *testing.T) {
	t.Parallel()
	addr := startServer(t,
		[]netip.Addr{netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2")},
		nil,
	)
	r := newResolver(t, addr)

	as, err := dnsclient.ResolveAs[rdata.A](t.Context(), r, wire.MustParseName("example.com"), rrtype.A)
	require.NoError(t, err)
	got := make([]string, len(as))
	for i, a := range as {
		got[i] = a.Addr().String()
	}
	slices.Sort(got)
	require.Equal(t, []string{"203.0.113.1", "203.0.113.2"}, got)
}

// ResolveAs[rdata.AAAA] paired with rrtype.A must return zero results — the
// owner type filter prevents structural-satisfaction collisions between
// rdata.A and rdata.AAAA.
func TestResolveAs_TypeFilterPreventsCollision(t *testing.T) {
	t.Parallel()
	addr := startServer(t,
		[]netip.Addr{netip.MustParseAddr("203.0.113.1")},
		nil,
	)
	r := newResolver(t, addr)

	as, err := dnsclient.ResolveAs[rdata.AAAA](t.Context(), r, wire.MustParseName("example.com"), rrtype.AAAA)
	require.NoError(t, err)
	require.Empty(t, as) // server returns no AAAA records
}
