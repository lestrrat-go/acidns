package sig0_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/lestrrat-go/acidns/sig0"
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

	signer := dnsname.MustParse("test.signer")
	wire := mkMessage(t)
	now := time.Now().Truncate(time.Second).UTC()

	signed, err := sig0.Sign(wire, signer, rdata.AlgRSASHA256, 1234,
		func(payload []byte) ([]byte, error) {
			h := sha256.Sum256(payload)
			return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
		}, now, time.Hour)
	require.NoError(t, err)

	_, err = sig0.Verify(signed, rdata.AlgRSASHA256, pubWire, signer, now.Add(30*time.Minute))
	require.NoError(t, err)
}

func TestVerifyUnsupportedAlgorithm(t *testing.T) {
	t.Parallel()
	wire := mkMessage(t)
	signer := dnsname.MustParse("s")
	signed, err := sig0.Sign(wire, signer, rdata.DNSSECAlgorithm(99), 1,
		func(p []byte) ([]byte, error) { return []byte{1, 2, 3}, nil },
		time.Now(), time.Hour)
	require.NoError(t, err)
	_, err = sig0.Verify(signed, rdata.DNSSECAlgorithm(99), nil, signer, time.Now())
	require.ErrorIs(t, err, sig0.ErrUnsupportedAlg)
}
