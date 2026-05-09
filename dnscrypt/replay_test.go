package dnscrypt

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestReplayCache(t *testing.T) {
	t.Parallel()
	c := newReplayCache(time.Minute, 8)
	pk := [32]byte{1}
	nonce := [12]byte{2}
	now := time.Unix(1_700_000_000, 0)

	require.False(t, c.seen(pk, nonce, now), "first observation must not be flagged")
	require.True(t, c.seen(pk, nonce, now), "second observation within window must be flagged")
	require.True(t, c.seen(pk, nonce, now.Add(30*time.Second)), "still within window")
	require.False(t, c.seen(pk, nonce, now.Add(2*time.Minute)), "outside the window: re-record, not a replay")

	other := [12]byte{3}
	require.False(t, c.seen(pk, other, now), "different nonce is not a replay")
	otherPK := [32]byte{4}
	require.False(t, c.seen(otherPK, nonce, now), "different clientPK is not a replay")
}

func TestReplayCacheBound(t *testing.T) {
	t.Parallel()
	c := newReplayCache(time.Hour, 4)
	now := time.Unix(1_700_000_000, 0)
	for i := range 32 {
		var pk [32]byte
		pk[0] = byte(i)
		c.seen(pk, [12]byte{}, now.Add(time.Duration(i)*time.Second))
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	require.LessOrEqual(t, len(c.entries), 4, "cache must respect max bound")
}
