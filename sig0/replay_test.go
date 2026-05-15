package sig0_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnssec"
	"github.com/lestrrat-go/acidns/sig0"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// signEd25519 builds a SIG(0)-signed wire envelope plus the matching
// DNSKEY. Inception is fixed so tests can drive the verifier with a
// deterministic clock.
func signEd25519(t *testing.T, qname string, inception time.Time, validity time.Duration) (
	signed []byte, key rdata.DNSKEY, signer wire.Name,
) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err = rdata.NewDNSKEY(257, 3, rdata.AlgED25519, pub)
	require.NoError(t, err)
	signer = wire.MustParseName("primary.example.")

	m, err := wire.NewMessageBuilder().
		ID(0xabcd).
		Question(wire.NewQuestion(wire.MustParseName(qname), rrtype.A)).
		Build()
	require.NoError(t, err)
	msg, err := wire.Pack(m)
	require.NoError(t, err)

	signed, err = sig0.Sign(msg, signer, rdata.AlgED25519, dnssec.KeyTag(key),
		func(payload []byte) ([]byte, error) { return ed25519.Sign(priv, payload), nil },
		inception, validity)
	require.NoError(t, err)
	return signed, key, signer
}

// TestMemoryReplayCacheSeen is the core invariant: a (signer, inception,
// signature) tuple seen twice within the window returns true on the
// second call.
func TestMemoryReplayCacheSeen(t *testing.T) {
	t.Parallel()
	c := sig0.NewMemoryReplayCache()
	signer := wire.MustParseName("primary.example.")
	inc := time.Unix(1_700_000_000, 0)
	sig := []byte{0xde, 0xad, 0xbe, 0xef}

	require.False(t, c.Seen(signer, inc, sig), "first observation must be fresh")
	require.True(t, c.Seen(signer, inc, sig), "second observation must be a replay")
}

// TestMemoryReplayCacheDifferentSigsAreDistinct guards against an
// accidental collision in the cache key derivation — two signatures that
// only differ in their last byte must hash to distinct entries.
func TestMemoryReplayCacheDifferentSigsAreDistinct(t *testing.T) {
	t.Parallel()
	c := sig0.NewMemoryReplayCache()
	signer := wire.MustParseName("primary.example.")
	inc := time.Unix(1_700_000_000, 0)

	require.False(t, c.Seen(signer, inc, []byte{0x01, 0x02, 0x03}))
	require.False(t, c.Seen(signer, inc, []byte{0x01, 0x02, 0x04}), "trailing-byte difference must register as a fresh signature")
}

// TestMemoryReplayCacheWindowExpiry advances a controlled clock past the
// retention window and verifies the entry is re-acceptable.
func TestMemoryReplayCacheWindowExpiry(t *testing.T) {
	t.Parallel()
	current := time.Unix(1_700_000_000, 0)
	c := sig0.NewMemoryReplayCache(
		sig0.WithReplayWindow(time.Minute),
		sig0.WithReplayClock(func() time.Time { return current }),
	)
	signer := wire.MustParseName("primary.example.")
	inc := time.Unix(1_699_900_000, 0)
	sig := []byte{0x42}

	require.False(t, c.Seen(signer, inc, sig))
	require.True(t, c.Seen(signer, inc, sig), "still inside the window — replay")

	// Step past the window. The next Seen sweeps the expired entry
	// before deciding, so the tuple is fresh again.
	current = current.Add(2 * time.Minute)
	require.False(t, c.Seen(signer, inc, sig), "window has elapsed — entry must be evicted")
}

// TestMemoryReplayCacheSizeCap guarantees that hitting the size cap
// evicts an old entry instead of pinning the map unboundedly.
func TestMemoryReplayCacheSizeCap(t *testing.T) {
	t.Parallel()
	c := sig0.NewMemoryReplayCache(sig0.WithReplayCacheSize(2))
	signer := wire.MustParseName("primary.example.")
	inc := time.Unix(1_700_000_000, 0)

	require.False(t, c.Seen(signer, inc, []byte{1}))
	require.False(t, c.Seen(signer, inc, []byte{2}))
	require.False(t, c.Seen(signer, inc, []byte{3}), "third insertion must succeed — oldest is evicted to make room")
	// The third insertion evicted the oldest ({1}); replaying {3}
	// should still register as a replay.
	require.True(t, c.Seen(signer, inc, []byte{3}))
}

// TestVerifyWithReplayDetectsDuplicate is the end-to-end happy path: two
// successive verifications of the same wire-format SIG(0) envelope, the
// second returning ErrReplay.
func TestVerifyWithReplayDetectsDuplicate(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0).UTC()
	signed, key, signer := signEd25519(t, "host.example.", now, time.Hour)

	cache := sig0.NewMemoryReplayCache()
	body, err := sig0.VerifyWithReplay(signed, key, signer, now, cache)
	require.NoError(t, err)
	require.NotEmpty(t, body)

	_, err = sig0.VerifyWithReplay(signed, key, signer, now, cache)
	require.ErrorIs(t, err, sig0.ErrReplay)
}

// TestVerifyWithReplayDoesNotPolluteOnBadSignature pins the security
// posture: the cache MUST NOT remember a signature that failed
// cryptographic verification. An attacker who can flood the verifier
// with junk should not be able to lock out legitimate signers.
func TestVerifyWithReplayDoesNotPolluteOnBadSignature(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0).UTC()
	signed, key, signer := signEd25519(t, "host.example.", now, time.Hour)

	// Tamper with the last byte of the signature.
	tampered := append([]byte(nil), signed...)
	tampered[len(tampered)-1] ^= 0xff

	cache := sig0.NewMemoryReplayCache()
	_, err := sig0.VerifyWithReplay(tampered, key, signer, now, cache)
	require.Error(t, err)
	require.NotErrorIs(t, err, sig0.ErrReplay, "bad signatures must not be added to the cache")

	// The same bytes again still fail with the original verification
	// error — they never reached the replay-check step.
	_, err2 := sig0.VerifyWithReplay(tampered, key, signer, now, cache)
	require.Error(t, err2)
	require.NotErrorIs(t, err2, sig0.ErrReplay)
}

// TestVerifyWithReplayNilCachePassesThrough documents the
// nil-cache-as-pass-through contract. A caller who hasn't wired up a
// cache yet still gets plain Verify semantics.
func TestVerifyWithReplayNilCachePassesThrough(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0).UTC()
	signed, key, signer := signEd25519(t, "host.example.", now, time.Hour)

	body1, err := sig0.VerifyWithReplay(signed, key, signer, now, nil)
	require.NoError(t, err)
	require.NotEmpty(t, body1)

	body2, err := sig0.VerifyWithReplay(signed, key, signer, now, nil)
	require.NoError(t, err, "without a cache, two identical messages both verify")
	require.Equal(t, body1, body2)
}

// TestVerifyWithReplayErrReplayIsMatchable confirms that callers can
// distinguish ErrReplay from generic verification failures via
// errors.Is.
func TestVerifyWithReplayErrReplayIsMatchable(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0).UTC()
	signed, key, signer := signEd25519(t, "host.example.", now, time.Hour)
	cache := sig0.NewMemoryReplayCache()

	_, err := sig0.VerifyWithReplay(signed, key, signer, now, cache)
	require.NoError(t, err)
	_, err = sig0.VerifyWithReplay(signed, key, signer, now, cache)
	require.True(t, errors.Is(err, sig0.ErrReplay))
}
