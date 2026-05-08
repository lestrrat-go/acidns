package tsig_test

import (
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/tsig"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/stretchr/testify/require"
)

// TestReplayCacheDetectsDuplicates exercises the basic "second
// observation of the same (key, time, MAC) tuple is a replay" path.
func TestReplayCacheDetectsDuplicates(t *testing.T) {
	t.Parallel()
	c := tsig.NewMemoryReplayCache()
	keyName := wire.MustParseName("k.example.")
	signedAt := time.Now()
	mac := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	require.False(t, c.Seen(keyName, signedAt, mac), "first observation is fresh")
	require.True(t, c.Seen(keyName, signedAt, mac), "duplicate is a replay")
}

// TestReplayCacheDistinctMACs verifies that the cache keys on the full
// (name, time, MAC) tuple — not just one component.
func TestReplayCacheDistinctMACs(t *testing.T) {
	t.Parallel()
	c := tsig.NewMemoryReplayCache()
	keyName := wire.MustParseName("k.example.")
	signedAt := time.Now()

	require.False(t, c.Seen(keyName, signedAt, []byte{1, 2, 3}))
	require.False(t, c.Seen(keyName, signedAt, []byte{4, 5, 6}),
		"different MAC must be admitted")
}

// TestReplayCacheWindowEviction verifies entries past the retention
// window are evicted and the same MAC can re-enter the cache.
func TestReplayCacheWindowEviction(t *testing.T) {
	t.Parallel()
	now := time.Now()
	clock := now
	c := tsig.NewMemoryReplayCache(
		tsig.WithReplayWindow(time.Minute),
		tsig.WithReplayClock(func() time.Time { return clock }),
	)
	keyName := wire.MustParseName("k.example.")
	mac := []byte{1, 2, 3}

	require.False(t, c.Seen(keyName, now, mac))
	require.True(t, c.Seen(keyName, now, mac))

	// Advance the clock past the retention window — the entry is
	// evicted on the next consultation and the MAC is admitted afresh.
	clock = now.Add(2 * time.Minute)
	require.False(t, c.Seen(keyName, now, mac),
		"entry must be evicted past window")
}

// TestReplayCacheSizeCap verifies the size cap is enforced.
func TestReplayCacheSizeCap(t *testing.T) {
	t.Parallel()
	c := tsig.NewMemoryReplayCache(tsig.WithReplayCacheSize(2))
	keyName := wire.MustParseName("k.example.")
	now := time.Now()

	c.Seen(keyName, now, []byte{1})
	c.Seen(keyName, now.Add(time.Second), []byte{2})
	c.Seen(keyName, now.Add(2*time.Second), []byte{3})

	// At cap=2 the oldest entry is evicted to make room.
	require.LessOrEqual(t, c.Len(), 2)
}
