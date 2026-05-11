package recursive_test

import (
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/recursive"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// fakeClock is a coarse manual clock for cache-TTL tests. Stored as a
// nanosecond Unix timestamp so reads/advances are atomic across
// goroutines.
type fakeClock struct{ nanos atomic.Int64 }

func newFakeClock(t time.Time) *fakeClock {
	c := &fakeClock{}
	c.nanos.Store(t.UnixNano())
	return c
}

func (c *fakeClock) Now() time.Time         { return time.Unix(0, c.nanos.Load()) }
func (c *fakeClock) Advance(d time.Duration) { c.nanos.Add(int64(d)) }

func TestCacheGetDecrementsTTL(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clk := newFakeClock(start)

	cache := recursive.NewMemoryCache(recursive.WithMemoryCacheClock(clk.Now))
	name := wire.MustParseName("a.test.")
	ar, err := rdata.NewA(netip.MustParseAddr("192.0.2.1"))
	require.NoError(t, err)
	rec := wire.NewRecord(name, 300*time.Second,
		ar)
	cache.Put(name, rrtype.ClassIN, rrtype.A, mustEntry(t, recursive.NewEntryBuilder().
		Answer([]wire.Record{rec}).
		ExpiresAt(start.Add(300*time.Second))))

	clk.Advance(100 * time.Second)
	got, ok := cache.Get(name, rrtype.ClassIN, rrtype.A)
	require.True(t, ok)
	require.Equal(t, 1, len(got.Answer()))
	require.Equal(t, 200*time.Second, got.Answer()[0].TTL())

	clk.Advance(200 * time.Second)
	_, ok = cache.Get(name, rrtype.ClassIN, rrtype.A)
	require.False(t, ok, "entry must be treated as expired once remaining TTL hits 0")
}
