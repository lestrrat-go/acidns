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
	ar, err := rdata.NewA(netip.MustParseAddr("192.0.2.1"))
	require.NoError(t, err)
	rec := wire.NewRecord(name, time.Hour,
		ar)
	c.Put(name, rrtype.ClassIN, rrtype.A, mustEntry(t, recursive.NewEntryBuilder().
		Answer([]wire.Record{rec}).
		ExpiresAt(time.Now().Add(time.Hour))))

	first, ok := c.Get(name, rrtype.ClassIN, rrtype.A)
	require.True(t, ok)
	firstAnswer := first.Answer()
	require.Equal(t, 1, len(firstAnswer))

	// Mutate the slice we got back. A second Get must see the
	// original record, not our perturbation.
	ar2, err := rdata.NewA(netip.MustParseAddr("198.51.100.99"))
	require.NoError(t, err)
	firstAnswer[0] = wire.NewRecord(name, time.Hour,
		ar2)

	second, ok := c.Get(name, rrtype.ClassIN, rrtype.A)
	require.True(t, ok)
	secondAnswer := second.Answer()
	require.Equal(t, 1, len(secondAnswer))
	a, ok := wire.RDataAs[rdata.A](secondAnswer[0])
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
	ar3, err := rdata.NewA(netip.MustParseAddr("192.0.2.1"))
	require.NoError(t, err)
	answer := []wire.Record{
		wire.NewRecord(name, time.Hour,
			ar3),
	}
	c.Put(name, rrtype.ClassIN, rrtype.A, mustEntry(t, recursive.NewEntryBuilder().
		Answer(answer).
		ExpiresAt(time.Now().Add(time.Hour))))

	// Mutate after Put.
	ar4, err := rdata.NewA(netip.MustParseAddr("198.51.100.99"))
	require.NoError(t, err)
	answer[0] = wire.NewRecord(name, time.Hour,
		ar4)

	got, ok := c.Get(name, rrtype.ClassIN, rrtype.A)
	require.True(t, ok)
	a, ok := wire.RDataAs[rdata.A](got.Answer()[0])
	require.True(t, ok)
	require.Equal(t, "192.0.2.1", a.Addr().String(),
		"cache must snapshot the caller's slice on Put")
}

// TestEntryBuilderSingleShot verifies that EntryBuilder.Build resets
// the builder so a second Build does not leak the first Entry's
// section slices or rcode/aa/ad bits.
func TestEntryBuilderSingleShot(t *testing.T) {
	t.Parallel()
	name := wire.MustParseName("a.test.")
	ar, err := rdata.NewA(netip.MustParseAddr("192.0.2.1"))
	require.NoError(t, err)
	rec := wire.NewRecord(name, time.Hour, ar)

	b := recursive.NewEntryBuilder().
		Answer([]wire.Record{rec}).
		RCODE(wire.RCODENoError).
		AA(true).
		AD(true).
		TTL(time.Hour)

	first, err := b.Build()
	require.NoError(t, err)
	require.Len(t, first.Answer(), 1)
	require.True(t, first.AA())
	require.True(t, first.AD())

	// Builder reset — second Build is the zero Entry.
	second, err := b.Build()
	require.NoError(t, err)
	require.Empty(t, second.Answer())
	require.False(t, second.AA(), "reset must clear AA")
	require.False(t, second.AD(), "reset must clear AD")

	// First Entry is unaffected.
	require.Len(t, first.Answer(), 1)
	require.True(t, first.AA())
}
