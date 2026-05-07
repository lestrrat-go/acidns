package wire_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

func TestRDataAs_Match(t *testing.T) {
	t.Parallel()
	name := wire.MustParseName("example.com")
	rec := wire.NewRecord(name, 60*time.Second, rdata.NewA(netip.MustParseAddr("192.0.2.1")))

	a, ok := wire.RDataAs[rdata.A](rec, rrtype.A)
	require.True(t, ok)
	require.Equal(t, "192.0.2.1", a.Addr().String())
}

// RDataAs[rdata.AAAA] paired with rrtype.AAAA on an A record must return
// (zero, false) — the rrtype gate prevents the structural-satisfaction
// collision between rdata.A and rdata.AAAA.
func TestRDataAs_TypeFilterPreventsACollision(t *testing.T) {
	t.Parallel()
	name := wire.MustParseName("example.com")
	rec := wire.NewRecord(name, 60*time.Second, rdata.NewA(netip.MustParseAddr("192.0.2.1")))

	v, ok := wire.RDataAs[rdata.AAAA](rec, rrtype.AAAA)
	require.False(t, ok)
	require.Nil(t, v)
}

// SVCB structurally satisfies CNAME (both expose Target()). Asking for CNAME
// when the record is SVCB must return (zero, false).
func TestRDataAs_TypeFilterPreventsCNAMECollision(t *testing.T) {
	t.Parallel()
	name := wire.MustParseName("example.com")
	target := wire.MustParseName("svc.example.net")
	rec := wire.NewRecord(name, 60*time.Second, rdata.NewSVCB(1, target))

	v, ok := wire.RDataAs[rdata.CNAME](rec, rrtype.CNAME)
	require.False(t, ok)
	require.Nil(t, v)
}

// Mismatched (T, rrtype.Type) pair: rrtype matches the record but T does not.
// Caught by the assertion, returns (zero, false) without panicking.
func TestRDataAs_AssertionFailure(t *testing.T) {
	t.Parallel()
	name := wire.MustParseName("example.com")
	rec := wire.NewRecord(name, 60*time.Second, rdata.NewA(netip.MustParseAddr("192.0.2.1")))

	v, ok := wire.RDataAs[rdata.MX](rec, rrtype.A)
	require.False(t, ok)
	require.Nil(t, v)
}
