package spki_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/internal/spki"
	"github.com/stretchr/testify/require"
)

func TestHashMatchesRawSPKI(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pin-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	got := spki.Hash(cert)
	want := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	require.Equal(t, want, got)
	require.Len(t, got, spki.HashSize)
	require.Equal(t, 32, spki.HashSize)
}

func TestHashStableAcrossReissue(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	// Re-issuing a cert with the same key but different serial /
	// validity / subject MUST yield the same SPKI hash; that property
	// is what makes pinning operationally usable across renewals.
	mk := func(serial int64) *x509.Certificate {
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: "pin-test"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
		require.NoError(t, err)
		c, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return c
	}
	a := spki.Hash(mk(1))
	b := spki.Hash(mk(2))
	require.Equal(t, a, b)
}
