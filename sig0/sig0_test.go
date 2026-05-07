package sig0_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/sig0"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

func mkMessage(t *testing.T) []byte {
	t.Helper()
	m, err := wire.NewBuilder().
		ID(0xbeef).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	require.NoError(t, err)
	msg, err := wire.Marshal(m)
	require.NoError(t, err)
	return msg
}

func TestSignVerifyECDSAP256(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	encPK, err2 := priv.PublicKey.Bytes()
	require.NoError(t, err2)
	pub := encPK[1:]

	signer := wire.MustParseName("test.signer")
	msg := mkMessage(t)
	now := time.Now().Truncate(time.Second).UTC()

	signed, err := sig0.Sign(msg, signer, rdata.AlgECDSAP256SHA256, 1234,
		func(payload []byte) ([]byte, error) {
			h := sha256.Sum256(payload)
			r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
			if err != nil {
				return nil, err
			}
			out := make([]byte, 64)
			r.FillBytes(out[:32])
			s.FillBytes(out[32:])
			return out, nil
		}, now, time.Hour)
	require.NoError(t, err)

	body, err := sig0.Verify(signed, rdata.AlgECDSAP256SHA256, pub, signer, now.Add(30*time.Minute))
	require.NoError(t, err)

	m, err := wire.Unmarshal(body)
	require.NoError(t, err)
	require.Equal(t, uint16(0xbeef), m.ID())
}

func TestSignVerifyED25519(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	signer := wire.MustParseName("test.signer")
	msg := mkMessage(t)
	now := time.Now().Truncate(time.Second).UTC()
	signed, err := sig0.Sign(msg, signer, rdata.AlgED25519, 5678,
		func(payload []byte) ([]byte, error) {
			return ed25519.Sign(priv, payload), nil
		}, now, time.Hour)
	require.NoError(t, err)
	_, err = sig0.Verify(signed, rdata.AlgED25519, pub, signer, now)
	require.NoError(t, err)
}

func TestVerifyExpiredFails(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer := wire.MustParseName("s")
	msg := mkMessage(t)
	signedAt := time.Now().Truncate(time.Second).UTC()
	signed, err := sig0.Sign(msg, signer, rdata.AlgED25519, 1, func(p []byte) ([]byte, error) {
		return ed25519.Sign(priv, p), nil
	}, signedAt, time.Minute)
	require.NoError(t, err)
	// Two hours later → outside validity.
	_, err = sig0.Verify(signed, rdata.AlgED25519, pub, signer, signedAt.Add(2*time.Hour))
	require.ErrorIs(t, err, sig0.ErrBadTime)
}

func TestVerifyTamperedFails(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer := wire.MustParseName("s")
	msg := mkMessage(t)
	now := time.Now().Truncate(time.Second).UTC()
	signed, err := sig0.Sign(msg, signer, rdata.AlgED25519, 1, func(p []byte) ([]byte, error) {
		return ed25519.Sign(priv, p), nil
	}, now, time.Hour)
	require.NoError(t, err)
	// Flip a bit in the QTYPE field.
	signed[26] ^= 0xff
	_, err = sig0.Verify(signed, rdata.AlgED25519, pub, signer, now)
	require.ErrorIs(t, err, sig0.ErrBadSignature)
}
