package recursive_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/recursive"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// TestCacheGetReturnsCopy verifies the immutability contract: mutating
// a slice returned by Get must NOT corrupt the cache's view of the
// entry. Without the deep copy a caller doing `e.Answer[0] = bad`
// would poison every other reader.
func TestCacheGetReturnsCopy(t *testing.T) {
	t.Parallel()
	c := recursive.NewMemoryCache()
	name := wire.MustParseName("a.test.")
	rec := wire.NewRecord(name, time.Hour,
		rdata.NewA(netip.MustParseAddr("192.0.2.1")))
	c.Put(name, rrtype.A, recursive.Entry{
		Answer:    []wire.Record{rec},
		ExpiresAt: time.Now().Add(time.Hour),
	})

	first, ok := c.Get(name, rrtype.A)
	require.True(t, ok)
	require.Equal(t, 1, len(first.Answer))

	// Mutate the slice we got back. A second Get must see the
	// original record, not our perturbation.
	first.Answer[0] = wire.NewRecord(name, time.Hour,
		rdata.NewA(netip.MustParseAddr("198.51.100.99")))

	second, ok := c.Get(name, rrtype.A)
	require.True(t, ok)
	require.Equal(t, 1, len(second.Answer))
	a, ok := wire.RDataAs[rdata.A](second.Answer[0])
	require.True(t, ok)
	require.Equal(t, "192.0.2.1", a.Addr().String())
}

// TestCachePutSnapshotsCaller verifies the symmetric contract: a
// later mutation of the slice the caller passed to Put must NOT
// retroactively corrupt the cache.
func TestCachePutSnapshotsCaller(t *testing.T) {
	t.Parallel()
	c := recursive.NewMemoryCache()
	name := wire.MustParseName("a.test.")
	answer := []wire.Record{
		wire.NewRecord(name, time.Hour,
			rdata.NewA(netip.MustParseAddr("192.0.2.1"))),
	}
	c.Put(name, rrtype.A, recursive.Entry{
		Answer:    answer,
		ExpiresAt: time.Now().Add(time.Hour),
	})

	// Mutate after Put.
	answer[0] = wire.NewRecord(name, time.Hour,
		rdata.NewA(netip.MustParseAddr("198.51.100.99")))

	got, ok := c.Get(name, rrtype.A)
	require.True(t, ok)
	a, ok := wire.RDataAs[rdata.A](got.Answer[0])
	require.True(t, ok)
	require.Equal(t, "192.0.2.1", a.Addr().String(),
		"cache must snapshot the caller's slice on Put")
}
