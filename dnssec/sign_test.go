package dnssec_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/lestrrat-go/acidns/dnssec"
	"github.com/stretchr/testify/require"
)

func TestSignedData(t *testing.T) {
	t.Parallel()
	set := []dnsmsg.Record{
		dnsmsg.NewRecord(dnsname.MustParse("a.example.com"), time.Hour,
			rdata.NewA(netip.MustParseAddr("192.0.2.1"))),
	}
	rrsig := rdata.NewRRSIG(set[0].Type(), rdata.AlgECDSAP256SHA256, 3,
		time.Hour, time.Now().Add(time.Hour), time.Now().Add(-time.Hour),
		1234, dnsname.MustParse("example.com"), nil)
	got, err := dnssec.SignedData(set, rrsig)
	require.NoError(t, err)
	require.Greater(t, len(got), 0)
}

func TestDSDigestAllAlgorithms(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub := append(priv.PublicKey.X.FillBytes(make([]byte, 32)), priv.PublicKey.Y.FillBytes(make([]byte, 32))...)
	key := rdata.NewDNSKEY(257, 3, rdata.AlgECDSAP256SHA256, pub)
	owner := dnsname.MustParse("example.com")

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
	pub := append(priv.PublicKey.X.FillBytes(make([]byte, 32)), priv.PublicKey.Y.FillBytes(make([]byte, 32))...)
	key := rdata.NewDNSKEY(257, 3, rdata.AlgECDSAP256SHA256, pub)
	owner := dnsname.MustParse("example.com")
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
	pub := append(priv.PublicKey.X.FillBytes(make([]byte, 32)), priv.PublicKey.Y.FillBytes(make([]byte, 32))...)
	key := rdata.NewDNSKEY(257, 3, rdata.AlgECDSAP256SHA256, pub)
	owner := dnsname.MustParse("example.com")
	ds := rdata.NewDS(dnssec.KeyTag(key), key.Algorithm(), rdata.DSDigestType(99), make([]byte, 32))
	require.ErrorIs(t, dnssec.VerifyDS(owner, ds, key), dnssec.ErrUnsupportedAlgorithm)
}

func TestVerifyKeyTagMismatch(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub := append(priv.PublicKey.X.FillBytes(make([]byte, 32)), priv.PublicKey.Y.FillBytes(make([]byte, 32))...)
	key := rdata.NewDNSKEY(257, 3, rdata.AlgECDSAP256SHA256, pub)
	rrsig := rdata.NewRRSIG(rrtype.A, rdata.AlgECDSAP256SHA256, 3,
		time.Hour, time.Now().Add(time.Hour), time.Now().Add(-time.Hour),
		dnssec.KeyTag(key)+1, // wrong tag
		dnsname.MustParse("example.com"), make([]byte, 64))
	set := []dnsmsg.Record{
		dnsmsg.NewRecord(dnsname.MustParse("a.example.com"), time.Hour,
			rdata.NewA(netip.MustParseAddr("192.0.2.1"))),
	}
	require.ErrorIs(t, dnssec.Verify(set, rrsig, key), dnssec.ErrSignatureMismatch)
}
