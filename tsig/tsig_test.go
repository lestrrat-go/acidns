package tsig_test

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/lestrrat-go/acidns/tsig"
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
	m, err := dnsmsg.NewBuilder().
		ID(0xabcd).
		RecursionDesired(true).
		Question(dnsmsg.NewQuestion(dnsname.MustParse("example.com"), rrtype.A)).
		Build()
	require.NoError(t, err)
	wire, err := dnsmsg.Marshal(m)
	require.NoError(t, err)
	return wire
}

func TestSignVerifyRoundTrip(t *testing.T) {
	t.Parallel()

	for _, alg := range []tsig.Algorithm{
		tsig.HMACSHA1, tsig.HMACSHA256, tsig.HMACSHA384, tsig.HMACSHA512,
	} {
		t.Run(string(alg), func(t *testing.T) {
			key := tsig.Key{
				Name:      dnsname.MustParse("test.key"),
				Algorithm: alg,
				Secret:    mkSecret(t, 32),
			}
			wire := mkMessage(t)
			now := time.Now().Truncate(time.Second)

			signed, err := tsig.Sign(wire, key, now, 5*time.Minute)
			require.NoError(t, err)
			require.Greater(t, len(signed), len(wire),
				"signed message must contain extra TSIG bytes")

			body, signedAt, err := tsig.Verify(signed, key, now, 5*time.Minute)
			require.NoError(t, err)
			require.Equal(t, now.UTC(), signedAt)

			m, err := dnsmsg.Unmarshal(body)
			require.NoError(t, err)
			require.Equal(t, uint16(0xabcd), m.ID())
			require.Equal(t, 1, len(m.Questions()))
		})
	}
}

func TestVerifyFailsOnTamper(t *testing.T) {
	t.Parallel()
	key := tsig.Key{
		Name: dnsname.MustParse("k"), Algorithm: tsig.HMACSHA256, Secret: mkSecret(t, 16),
	}
	wire := mkMessage(t)
	now := time.Now().Truncate(time.Second)
	signed, err := tsig.Sign(wire, key, now, 5*time.Minute)
	require.NoError(t, err)

	// Flip the low byte of QTYPE — keeps the wire well-formed but
	// changes what HMAC was computed over.
	signed[26] ^= 0xfe
	_, _, err = tsig.Verify(signed, key, now, 5*time.Minute)
	require.ErrorIs(t, err, tsig.ErrBadSignature)
}

func TestVerifyFailsOnWrongSecret(t *testing.T) {
	t.Parallel()
	signKey := tsig.Key{
		Name: dnsname.MustParse("k"), Algorithm: tsig.HMACSHA256, Secret: mkSecret(t, 16),
	}
	verKey := signKey
	verKey.Secret = mkSecret(t, 16)

	wire := mkMessage(t)
	now := time.Now().Truncate(time.Second)
	signed, err := tsig.Sign(wire, signKey, now, 5*time.Minute)
	require.NoError(t, err)

	_, _, err = tsig.Verify(signed, verKey, now, 5*time.Minute)
	require.ErrorIs(t, err, tsig.ErrBadSignature)
}

func TestVerifyClockSkewExceedsFudge(t *testing.T) {
	t.Parallel()
	key := tsig.Key{
		Name: dnsname.MustParse("k"), Algorithm: tsig.HMACSHA256, Secret: mkSecret(t, 16),
	}
	wire := mkMessage(t)
	signedAt := time.Now().Truncate(time.Second)
	signed, err := tsig.Sign(wire, key, signedAt, 60*time.Second)
	require.NoError(t, err)

	// Verify pretending it's two hours later — outside fudge.
	later := signedAt.Add(2 * time.Hour)
	_, _, err = tsig.Verify(signed, key, later, 60*time.Second)
	require.ErrorIs(t, err, tsig.ErrBadTime)
}

func TestVerifyMissingTSIG(t *testing.T) {
	t.Parallel()
	wire := mkMessage(t)
	key := tsig.Key{
		Name: dnsname.MustParse("k"), Algorithm: tsig.HMACSHA256, Secret: mkSecret(t, 16),
	}
	_, _, err := tsig.Verify(wire, key, time.Now(), time.Minute)
	require.ErrorIs(t, err, tsig.ErrTSIGMissing)
}
