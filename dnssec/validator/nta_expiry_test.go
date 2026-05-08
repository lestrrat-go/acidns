package validator

import (
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/stretchr/testify/require"
)

func newNTAStoreWithClock(now func() time.Time) *NTAStore {
	return &NTAStore{
		set: make(map[string]ntaEntry),
		now: now,
	}
}

func TestNTAStoreEntryExpires(t *testing.T) {
	t.Parallel()

	clock := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	advance := time.Duration(0)
	s := newNTAStoreWithClock(func() time.Time { return clock.Add(advance) })

	require.True(t, s.Add(wire.MustParseName("de"), time.Hour))
	require.True(t, s.Covers(wire.MustParseName("denic.de")))

	// Just before expiry — still covered.
	advance = time.Hour - time.Second
	require.True(t, s.Covers(wire.MustParseName("denic.de")))

	// At/after expiry — no longer covered, and the entry is swept.
	advance = time.Hour + time.Second
	require.False(t, s.Covers(wire.MustParseName("denic.de")),
		"expired NTA must no longer cover its descendants")
	require.Empty(t, s.Names(),
		"Names must omit expired entries")
}

func TestNTAStoreAddRefreshesExpiry(t *testing.T) {
	t.Parallel()

	clock := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	advance := time.Duration(0)
	s := newNTAStoreWithClock(func() time.Time { return clock.Add(advance) })

	require.True(t, s.Add(wire.MustParseName("de"), time.Hour))

	// Half-way through the original TTL, refresh.
	advance = 30 * time.Minute
	require.False(t, s.Add(wire.MustParseName("de"), time.Hour),
		"existing entry returns false from Add")

	// Past the original expiry but inside the renewed window.
	advance = 70 * time.Minute
	require.True(t, s.Covers(wire.MustParseName("denic.de")),
		"renewed entry must still cover descendants past original expiry")

	// Past the renewed expiry too.
	advance = 100 * time.Minute
	require.False(t, s.Covers(wire.MustParseName("denic.de")))
}

func TestNTAStoreClampsTTL(t *testing.T) {
	t.Parallel()

	clock := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	advance := time.Duration(0)
	s := newNTAStoreWithClock(func() time.Time { return clock.Add(advance) })

	// Far past the supposed lifetime — but the cap is MaxNTATTL.
	require.True(t, s.Add(wire.MustParseName("de"), 365*24*time.Hour))

	advance = MaxNTATTL - time.Minute
	require.True(t, s.Covers(wire.MustParseName("de")),
		"should still cover within the clamped MaxNTATTL window")

	advance = MaxNTATTL + time.Minute
	require.False(t, s.Covers(wire.MustParseName("de")),
		"add with ttl beyond MaxNTATTL must clamp at one week, not honour the larger value")
}
