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

func mkSecret(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}

func mkMessage(t *testing.T) []byte {
	t.Helper()
	m, err := wire.NewMessageBuilder().
		ID(0xabcd).
		RecursionDesired(true).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	require.NoError(t, err)
	msg, err := wire.Marshal(m)
	require.NoError(t, err)
	return msg
}

func TestSignVerifyRoundTrip(t *testing.T) {
	t.Parallel()

	for _, alg := range []tsig.Algorithm{
		tsig.HMACSHA1, tsig.HMACSHA256, tsig.HMACSHA384, tsig.HMACSHA512,
	} {
		t.Run(string(alg), func(t *testing.T) {
			t.Parallel()
			var keyOpts []tsig.KeyOption
			if alg == tsig.HMACSHA1 {
				keyOpts = append(keyOpts, tsig.WithAllowSHA1(true))
			}
			key := tsig.NewKey(wire.MustParseName("test.key"), alg, mkSecret(t, 32), keyOpts...)
			msg := mkMessage(t)
			now := time.Now().Truncate(time.Second)

			signed, err := tsig.Sign(msg, key, now, 5*time.Minute)
			require.NoError(t, err)
			require.Greater(t, len(signed), len(msg),
				"signed message must contain extra TSIG bytes")

			body, signedAt, err := tsig.Verify(signed, key, now, 5*time.Minute)
			require.NoError(t, err)
			require.Equal(t, now.UTC(), signedAt)

			m, err := wire.Unmarshal(body)
			require.NoError(t, err)
			require.Equal(t, uint16(0xabcd), m.ID())
			require.Equal(t, 1, len(m.Questions()))
		})
	}
}

// TestSHA1DisabledByDefault confirms a key constructed with HMACSHA1
// fails Sign/Verify with ErrSHA1Disabled unless WithAllowSHA1 is set.
func TestSHA1DisabledByDefault(t *testing.T) {
	t.Parallel()
	key := tsig.NewKey(wire.MustParseName("legacy.key"), tsig.HMACSHA1, mkSecret(t, 20))
	_, err := tsig.Sign(mkMessage(t), key, time.Now(), 5*time.Minute)
	require.ErrorIs(t, err, tsig.ErrSHA1Disabled)

	allowed := tsig.NewKey(wire.MustParseName("legacy.key"), tsig.HMACSHA1, mkSecret(t, 20),
		tsig.WithAllowSHA1(true))
	signed, err := tsig.Sign(mkMessage(t), allowed, time.Now(), 5*time.Minute)
	require.NoError(t, err)
	require.NotEmpty(t, signed)
}

func TestVerifyFailsOnTamper(t *testing.T) {
	t.Parallel()
	key := tsig.NewKey(wire.MustParseName("k"), tsig.HMACSHA256, mkSecret(t, 16))
	msg := mkMessage(t)
	now := time.Now().Truncate(time.Second)
	signed, err := tsig.Sign(msg, key, now, 5*time.Minute)
	require.NoError(t, err)

	// Flip the low byte of QTYPE — keeps the msg well-formed but
	// changes what HMAC was computed over.
	signed[26] ^= 0xfe
	_, _, err = tsig.Verify(signed, key, now, 5*time.Minute)
	require.ErrorIs(t, err, tsig.ErrBadSignature)
}

func TestVerifyFailsOnWrongSecret(t *testing.T) {
	t.Parallel()
	signKey := tsig.NewKey(wire.MustParseName("k"), tsig.HMACSHA256, mkSecret(t, 16))
	verKey := tsig.NewKey(wire.MustParseName("k"), tsig.HMACSHA256, mkSecret(t, 16))

	msg := mkMessage(t)
	now := time.Now().Truncate(time.Second)
	signed, err := tsig.Sign(msg, signKey, now, 5*time.Minute)
	require.NoError(t, err)

	_, _, err = tsig.Verify(signed, verKey, now, 5*time.Minute)
	require.ErrorIs(t, err, tsig.ErrBadSignature)
}

func TestVerifyClockSkewExceedsFudge(t *testing.T) {
	t.Parallel()
	key := tsig.NewKey(wire.MustParseName("k"), tsig.HMACSHA256, mkSecret(t, 16))
	msg := mkMessage(t)
	signedAt := time.Now().Truncate(time.Second)
	signed, err := tsig.Sign(msg, key, signedAt, 60*time.Second)
	require.NoError(t, err)

	// Verify pretending it's two hours later — outside fudge.
	later := signedAt.Add(2 * time.Hour)
	_, _, err = tsig.Verify(signed, key, later, 60*time.Second)
	require.ErrorIs(t, err, tsig.ErrBadTime)
}

func TestVerifyMissingTSIG(t *testing.T) {
	t.Parallel()
	msg := mkMessage(t)
	key := tsig.NewKey(wire.MustParseName("k"), tsig.HMACSHA256, mkSecret(t, 16))
	_, _, err := tsig.Verify(msg, key, time.Now(), time.Minute)
	require.ErrorIs(t, err, tsig.ErrTSIGMissing)
}
