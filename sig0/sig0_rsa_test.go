package sig0_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnssec"
	"github.com/lestrrat-go/acidns/sig0"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/stretchr/testify/require"
)

func TestSignVerifyRSASHA256(t *testing.T) {
	t.Parallel()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	expBytes := big.NewInt(int64(priv.E)).Bytes()
	pubWire := make([]byte, 0, 1+len(expBytes)+len(priv.N.Bytes()))
	pubWire = append(pubWire, byte(len(expBytes)))
	pubWire = append(pubWire, expBytes...)
	pubWire = append(pubWire, priv.N.Bytes()...)
	key := rdata.NewDNSKEY(257, 3, rdata.AlgRSASHA256, pubWire)

	signer := wire.MustParseName("test.signer")
	msg := mkMessage(t)
	now := time.Now().Truncate(time.Second).UTC()

	signed, err := sig0.Sign(msg, signer, rdata.AlgRSASHA256, dnssec.KeyTag(key),
		func(payload []byte) ([]byte, error) {
			h := sha256.Sum256(payload)
			return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
		}, now, time.Hour)
	require.NoError(t, err)

	_, err = sig0.Verify(signed, key, signer, now.Add(30*time.Minute))
	require.NoError(t, err)
}

func TestVerifyUnsupportedAlgorithm(t *testing.T) {
	t.Parallel()
	msg := mkMessage(t)
	signer := wire.MustParseName("s")
	// Algorithm 99 is unassigned; key+SIG share it so the alg-equality
	// check passes, keytag matches, and verifySignature's default branch
	// returns ErrUnsupportedAlg.
	key := rdata.NewDNSKEY(257, 3, rdata.DNSSECAlgorithm(99), nil)
	signed, err := sig0.Sign(msg, signer, rdata.DNSSECAlgorithm(99), dnssec.KeyTag(key),
		func(_ []byte) ([]byte, error) { return []byte{1, 2, 3}, nil },
		time.Now(), time.Hour)
	require.NoError(t, err)
	_, err = sig0.Verify(signed, key, signer, time.Now())
	require.ErrorIs(t, err, sig0.ErrUnsupportedAlg)
}
