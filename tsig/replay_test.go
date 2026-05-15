package tsig_test

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/tsig"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
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

// verifyReplayErr runs tsig.VerifyWithReplay and discards everything
// except the error. Lets the call sites that only care about the error
// path avoid the 4-return dogsled warning.
func verifyReplayErr(msg []byte, key tsig.Key, cache tsig.ReplayCache, now time.Time, fudge time.Duration) error {
	_, _, _, err := tsig.VerifyWithReplay(msg, key, cache, now, fudge) //nolint:dogsled // only error is needed here
	return err
}

// signedTSIGEnvelope builds a TSIG-signed wire envelope using a freshly
// generated HMAC-SHA256 key. Used by the VerifyWithReplay tests.
func signedTSIGEnvelope(t *testing.T, now time.Time) ([]byte, tsig.Key) {
	t.Helper()
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	require.NoError(t, err)
	key, err := tsig.NewKey(wire.MustParseName("k.example."), tsig.HMACSHA256, secret)
	require.NoError(t, err)
	q, err := wire.NewMessageBuilder().
		ID(0x1234).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	require.NoError(t, err)
	signed, err := tsig.SignMessage(q, key, now, 5*time.Minute)
	require.NoError(t, err)
	return signed, key
}

// TestVerifyWithReplayDetectsDuplicate is the canonical happy path: a
// second VerifyWithReplay call on the same wire envelope returns
// ErrReplay.
func TestVerifyWithReplayDetectsDuplicate(t *testing.T) {
	t.Parallel()
	now := time.Now().Truncate(time.Second)
	signed, key := signedTSIGEnvelope(t, now)
	cache := tsig.NewMemoryReplayCache()

	body, mac, signedAt, err := tsig.VerifyWithReplay(signed, key, cache, now, 5*time.Minute)
	require.NoError(t, err)
	require.NotEmpty(t, body)
	require.NotEmpty(t, mac)
	// VerifyMAC returns signedAt parsed from the wire (UTC). The
	// caller's now may be in a different zone but the instants must
	// coincide.
	require.True(t, now.Equal(signedAt), "signedAt %v should equal now %v", signedAt, now)

	require.ErrorIs(t, verifyReplayErr(signed, key, cache, now, 5*time.Minute), tsig.ErrReplay)
}

// TestVerifyWithReplayDoesNotPolluteOnBadMAC pins the security posture:
// a tampered envelope must fail verification BEFORE its MAC is inserted
// into the cache. Otherwise an attacker flooding bad MACs could lock
// the cache out for legitimate signers (or, with a clever choice of
// fake MAC bytes, pre-poison a legitimate MAC's slot).
func TestVerifyWithReplayDoesNotPolluteOnBadMAC(t *testing.T) {
	t.Parallel()
	now := time.Now().Truncate(time.Second)
	signed, key := signedTSIGEnvelope(t, now)
	tampered := append([]byte(nil), signed...)
	tampered[len(tampered)-1] ^= 0xff
	cache := tsig.NewMemoryReplayCache()

	err := verifyReplayErr(tampered, key, cache, now, 5*time.Minute)
	require.Error(t, err)
	require.NotErrorIs(t, err, tsig.ErrReplay)

	// The legitimate envelope must still be admitted — the bad attempt
	// did not pollute the cache.
	require.NoError(t, verifyReplayErr(signed, key, cache, now, 5*time.Minute))
}

// TestVerifyWithReplayNilCachePassesThrough documents the
// nil-cache-as-pass-through contract.
func TestVerifyWithReplayNilCachePassesThrough(t *testing.T) {
	t.Parallel()
	now := time.Now().Truncate(time.Second)
	signed, key := signedTSIGEnvelope(t, now)

	require.NoError(t, verifyReplayErr(signed, key, nil, now, 5*time.Minute))
	require.NoError(t, verifyReplayErr(signed, key, nil, now, 5*time.Minute),
		"without a cache, two identical envelopes both verify")
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
	const maxSize = 4
	c := tsig.NewMemoryReplayCache(
		tsig.WithReplayCacheSize(maxSize),
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
	require.Equal(t, maxSize, c.Len(), "cache should be full")

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
