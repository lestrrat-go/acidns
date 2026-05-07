package dnssec_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnssec"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

func TestSignedData(t *testing.T) {
	t.Parallel()
	set := []wire.Record{
		wire.NewRecord(wire.MustParseName("a.example.com"), time.Hour,
			rdata.NewA(netip.MustParseAddr("192.0.2.1"))),
	}
	rrsig := rdata.NewRRSIG(set[0].Type(), rdata.AlgECDSAP256SHA256, 3,
		time.Hour, time.Now().Add(time.Hour), time.Now().Add(-time.Hour),
		1234, wire.MustParseName("example.com"), nil)
	got, err := dnssec.SignedData(set, rrsig)
	require.NoError(t, err)
	require.Greater(t, len(got), 0)
}

func TestDSDigestAllAlgorithms(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	encPK, err2 := priv.PublicKey.Bytes()
	require.NoError(t, err2)
	pub := encPK[1:]
	key := rdata.NewDNSKEY(257, 3, rdata.AlgECDSAP256SHA256, pub)
	owner := wire.MustParseName("example.com")

	for _, dt := range []rdata.DSDigestType{rdata.DigestSHA1, rdata.DigestSHA256, rdata.DigestSHA384} {
		d, err := dnssec.DSDigest(owner, key, dt)
		require.NoError(t, err)
		require.NotEmpty(t, d)
	}

	_, err = dnssec.DSDigest(owner, key, rdata.DSDigestType(99))
	require.ErrorIs(t, err, dnssec.ErrUnsupportedAlgorithm)
}

func TestVerifyDSAlgorithmMismatch(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	encPK, err2 := priv.PublicKey.Bytes()
	require.NoError(t, err2)
	pub := encPK[1:]
	key := rdata.NewDNSKEY(257, 3, rdata.AlgECDSAP256SHA256, pub)
	owner := wire.MustParseName("example.com")
	digest, err := dnssec.DSDigest(owner, key, rdata.DigestSHA256)
	require.NoError(t, err)
	// DS reports a different algorithm than the DNSKEY.
	ds := rdata.NewDS(dnssec.KeyTag(key), rdata.AlgED25519, rdata.DigestSHA256, digest)
	require.ErrorIs(t, dnssec.VerifyDS(owner, ds, key), dnssec.ErrSignatureMismatch)
}

func TestVerifyDSUnsupportedDigest(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	encPK, err2 := priv.PublicKey.Bytes()
	require.NoError(t, err2)
	pub := encPK[1:]
	key := rdata.NewDNSKEY(257, 3, rdata.AlgECDSAP256SHA256, pub)
	owner := wire.MustParseName("example.com")
	ds := rdata.NewDS(dnssec.KeyTag(key), key.Algorithm(), rdata.DSDigestType(99), make([]byte, 32))
	require.ErrorIs(t, dnssec.VerifyDS(owner, ds, key), dnssec.ErrUnsupportedAlgorithm)
}

func TestVerifyKeyTagMismatch(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	encPK, err2 := priv.PublicKey.Bytes()
	require.NoError(t, err2)
	pub := encPK[1:]
	key := rdata.NewDNSKEY(257, 3, rdata.AlgECDSAP256SHA256, pub)
	rrsig := rdata.NewRRSIG(rrtype.A, rdata.AlgECDSAP256SHA256, 3,
		time.Hour, time.Now().Add(time.Hour), time.Now().Add(-time.Hour),
		dnssec.KeyTag(key)+1, // wrong tag
		wire.MustParseName("example.com"), make([]byte, 64))
	set := []wire.Record{
		wire.NewRecord(wire.MustParseName("a.example.com"), time.Hour,
			rdata.NewA(netip.MustParseAddr("192.0.2.1"))),
	}
	require.ErrorIs(t, dnssec.Verify(set, rrsig, key), dnssec.ErrSignatureMismatch)
}
