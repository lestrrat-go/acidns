package wire_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/stretchr/testify/require"
)

func TestRDataAs_Match(t *testing.T) {
	t.Parallel()
	name := wire.MustParseName("example.com")
	rec := wire.NewRecord(name, 60*time.Second, rdata.NewA(netip.MustParseAddr("192.0.2.1")))

	a, ok := wire.RDataAs[rdata.A](rec)
	require.True(t, ok)
	require.Equal(t, "192.0.2.1", a.Addr().String())
}

// RDataAs[rdata.AAAA] on an A record must return (zero, false) — the
// inferred type gate (T's zero value reports rrtype.AAAA, record's type is
// A, so they don't match) prevents the structural-satisfaction collision
// that would otherwise let the assertion succeed.
func TestRDataAs_TypeFilterPreventsACollision(t *testing.T) {
	t.Parallel()
	name := wire.MustParseName("example.com")
	rec := wire.NewRecord(name, 60*time.Second, rdata.NewA(netip.MustParseAddr("192.0.2.1")))

	v, ok := wire.RDataAs[rdata.AAAA](rec)
	require.False(t, ok)
	require.Equal(t, rdata.AAAA{}, v)
}

// SVCB and CNAME used to share Target(), so an SVCB asserted to CNAME
// would have succeeded under the old interface-typed rdata. With the
// concrete-struct refactor these are now distinct types — but we still
// assert the rrtype gate keeps the assertion pristine.
func TestRDataAs_TypeFilterPreventsCNAMECollision(t *testing.T) {
	t.Parallel()
	name := wire.MustParseName("example.com")
	target := wire.MustParseName("svc.example.net")
	rec := wire.NewRecord(name, 60*time.Second, rdata.NewSVCB(1, target))

	v, ok := wire.RDataAs[rdata.CNAME](rec)
	require.False(t, ok)
	require.Equal(t, rdata.CNAME{}, v)
}

// Asking for a T whose rrtype doesn't match the record's type returns
// (zero, false) without panicking.
func TestRDataAs_TypeMismatch(t *testing.T) {
	t.Parallel()
	name := wire.MustParseName("example.com")
	rec := wire.NewRecord(name, 60*time.Second, rdata.NewA(netip.MustParseAddr("192.0.2.1")))

	v, ok := wire.RDataAs[rdata.MX](rec)
	require.False(t, ok)
	require.Equal(t, rdata.MX{}, v)
}
