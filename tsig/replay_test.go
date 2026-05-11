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

// TestReplayCacheReplayerDoesNotPinEntry guards against a regression
// where a hit refreshed the cached timestamp. Under sustained replay
// that behaviour kept the offender's entry "fresh" forever, so the
// oldest-entry eviction preferentially threw out legitimate entries
// while the replayer stayed pinned. The fix preserves the original
// observation time so the replayer ages out normally.
func TestReplayCacheReplayerDoesNotPinEntry(t *testing.T) {
	t.Parallel()

	clock := time.Unix(1_700_000_000, 0)
	const cap = 4
	c := tsig.NewMemoryReplayCache(
		tsig.WithReplayCacheSize(cap),
		// Large window so eviction is driven by the size cap, not
		// by window expiry — this is the path that exercised the
		// bug.
		tsig.WithReplayWindow(time.Hour),
		tsig.WithReplayClock(func() time.Time { return clock }),
	)
	keyName := wire.MustParseName("k.example.")

	// 1) Inject the replayer first so it is the oldest entry.
	replayerMAC := []byte{0xAA}
	replayerSignedAt := clock
	require.False(t, c.Seen(keyName, replayerSignedAt, replayerMAC),
		"replayer's first observation must be fresh")

	// 2) Fill the rest of the cache with legitimate entries, each
	//    with a distinct (signedAt, MAC). Advance the clock between
	//    each so their stored timestamps are monotonically newer
	//    than the replayer's.
	legitMACs := [][]byte{{0x01}, {0x02}, {0x03}}
	legitSignedAts := make([]time.Time, len(legitMACs))
	for i, mac := range legitMACs {
		clock = clock.Add(time.Second)
		legitSignedAts[i] = clock
		require.False(t, c.Seen(keyName, legitSignedAts[i], mac),
			"legitimate entry %d must be fresh", i)
	}
	require.Equal(t, cap, c.Len(), "cache should be full")

	// 3) Replay the offender many times. Each call must be reported
	//    as a replay; with the buggy refresh-on-hit behaviour the
	//    replayer's stored timestamp would advance past every
	//    legitimate entry's.
	for i := 0; i < 20; i++ {
		clock = clock.Add(time.Second)
		require.True(t, c.Seen(keyName, replayerSignedAt, replayerMAC),
			"replay #%d must be flagged", i)
	}

	// 4) Insert a brand new legitimate entry. This pushes the cache
	//    over capacity, forcing evictOldestLocked to drop exactly
	//    one entry.
	clock = clock.Add(time.Second)
	newMAC := []byte{0x04}
	newSignedAt := clock
	require.False(t, c.Seen(keyName, newSignedAt, newMAC),
		"new legitimate entry must be admitted")

	// 5) Verify the legitimate entries from step 2 are still
	//    cached (i.e. they were NOT preferentially evicted while
	//    the replayer was being repeatedly hit). Each Seen() call
	//    on a still-cached tuple returns true (replay).
	for i, mac := range legitMACs {
		require.True(t, c.Seen(keyName, legitSignedAts[i], mac),
			"legitimate entry %d must still be cached", i)
	}

	// 6) The replayer (oldest by original-observation time) must
	//    have been the entry evicted in step 4. Re-observing its
	//    tuple should be treated as fresh, not a replay.
	require.False(t, c.Seen(keyName, replayerSignedAt, replayerMAC),
		"replayer entry must have been evicted, not pinned")
}
