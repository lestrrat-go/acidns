package validator_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnssec"
	"github.com/lestrrat-go/acidns/dnssec/validator"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/stretchr/testify/require"
)

func makeECDSAP256Key(t *testing.T) (*ecdsa.PrivateKey, rdata.DNSKEY) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub := append(priv.PublicKey.X.FillBytes(make([]byte, 32)), priv.PublicKey.Y.FillBytes(make([]byte, 32))...)
	key := rdata.NewDNSKEY(257, 3, rdata.AlgECDSAP256SHA256, pub)
	return priv, key
}

func signRRSIG(t *testing.T, priv *ecdsa.PrivateKey, set []wire.Record, key rdata.DNSKEY, inception, expiration time.Time) rdata.RRSIG {
	t.Helper()
	signer := set[0].Name()
	skeleton := rdata.NewRRSIG(set[0].Type(), rdata.AlgECDSAP256SHA256,
		uint8(set[0].Name().NumLabels()), set[0].TTL(),
		expiration, inception, dnssec.KeyTag(key), signer, nil)
	payload, err := dnssec.SignedData(set, skeleton)
	require.NoError(t, err)
	h := sha256.Sum256(payload)
	r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
	require.NoError(t, err)
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return rdata.NewRRSIG(set[0].Type(), rdata.AlgECDSAP256SHA256,
		uint8(set[0].Name().NumLabels()), set[0].TTL(),
		expiration, inception, dnssec.KeyTag(key), signer, sig)
}

func TestValidateRRsetSecure(t *testing.T) {
	t.Parallel()
	priv, key := makeECDSAP256Key(t)
	now := time.Now().UTC().Truncate(time.Second)
	set := []wire.Record{
		wire.NewRecord(wire.MustParseName("example.com"), time.Hour,
			rdata.NewA(netip.MustParseAddr("192.0.2.1"))),
	}
	sig := signRRSIG(t, priv, set, key, now.Add(-time.Hour), now.Add(time.Hour))

	v := validator.New(validator.Options{Now: func() time.Time { return now }})
	res, used, err := v.ValidateRRset(set, []rdata.RRSIG{sig}, []rdata.DNSKEY{key})
	require.NoError(t, err)
	require.Equal(t, validator.Secure, res)
	require.NotNil(t, used)
}

func TestValidateRRsetEmptySet(t *testing.T) {
	t.Parallel()
	v := validator.New(validator.Options{})
	_, _, err := v.ValidateRRset(nil, nil, nil)
	require.Error(t, err)
}

func TestValidateRRsetNoRRSIG(t *testing.T) {
	t.Parallel()
	v := validator.New(validator.Options{})
	set := []wire.Record{
		wire.NewRecord(wire.MustParseName("example.com"), time.Hour,
			rdata.NewA(netip.MustParseAddr("192.0.2.1"))),
	}
	res, _, err := v.ValidateRRset(set, nil, nil)
	require.Equal(t, validator.Bogus, res)
	require.ErrorIs(t, err, validator.ErrNoCoveringRRSIG)
}

func TestValidateRRsetNTAShortCircuits(t *testing.T) {
	t.Parallel()
	store := validator.NewNTAStore(wire.MustParseName("example.com"))
	v := validator.New(validator.Options{NTAs: store})
	set := []wire.Record{
		wire.NewRecord(wire.MustParseName("example.com"), time.Hour,
			rdata.NewA(netip.MustParseAddr("192.0.2.1"))),
	}
	res, _, err := v.ValidateRRset(set, nil, nil)
	require.NoError(t, err)
	require.Equal(t, validator.Indeterminate, res)
}

func TestValidateRRsetExpiredRRSIG(t *testing.T) {
	t.Parallel()
	priv, key := makeECDSAP256Key(t)
	now := time.Now().UTC().Truncate(time.Second)
	set := []wire.Record{
		wire.NewRecord(wire.MustParseName("example.com"), time.Hour,
			rdata.NewA(netip.MustParseAddr("192.0.2.1"))),
	}
	// Inception/expiration both in the past.
	sig := signRRSIG(t, priv, set, key, now.Add(-2*time.Hour), now.Add(-time.Hour))

	v := validator.New(validator.Options{
		Now:         func() time.Time { return now },
		BogusPolicy: validator.BogusReturnAnswer,
	})
	res, _, err := v.ValidateRRset(set, []rdata.RRSIG{sig}, []rdata.DNSKEY{key})
	require.Equal(t, validator.Bogus, res)
	require.Error(t, err)
}

func TestValidateRRsetNoMatchingKey(t *testing.T) {
	t.Parallel()
	priv, key := makeECDSAP256Key(t)
	now := time.Now().UTC().Truncate(time.Second)
	set := []wire.Record{
		wire.NewRecord(wire.MustParseName("example.com"), time.Hour,
			rdata.NewA(netip.MustParseAddr("192.0.2.1"))),
	}
	sig := signRRSIG(t, priv, set, key, now.Add(-time.Hour), now.Add(time.Hour))

	// Pass a wrong-algorithm key (synthetic).
	wrongKey := rdata.NewDNSKEY(257, 3, rdata.AlgED25519, make([]byte, 32))
	v := validator.New(validator.Options{
		Now:         func() time.Time { return now },
		BogusPolicy: validator.BogusReturnAnswer,
	})
	res, _, err := v.ValidateRRset(set, []rdata.RRSIG{sig}, []rdata.DNSKEY{wrongKey})
	require.Equal(t, validator.Bogus, res)
	require.Error(t, err)
}

func TestVerifyDelegationSecure(t *testing.T) {
	t.Parallel()
	_, key := makeECDSAP256Key(t)
	owner := wire.MustParseName("example.com")
	// Build a real DS that matches.
	digest, err := dnssec.DSDigest(owner, key, rdata.DigestSHA256)
	require.NoError(t, err)
	ds := rdata.NewDS(dnssec.KeyTag(key), key.Algorithm(), rdata.DigestSHA256, digest)

	v := validator.New(validator.Options{})
	res, err := v.VerifyDelegation(owner, []rdata.DS{ds}, []rdata.DNSKEY{key})
	require.NoError(t, err)
	require.Equal(t, validator.Secure, res)
}

func TestVerifyDelegationBogus(t *testing.T) {
	t.Parallel()
	_, key := makeECDSAP256Key(t)
	owner := wire.MustParseName("example.com")
	// Bogus DS — random bytes.
	ds := rdata.NewDS(dnssec.KeyTag(key), key.Algorithm(), rdata.DigestSHA256, make([]byte, 32))
	v := validator.New(validator.Options{})
	res, err := v.VerifyDelegation(owner, []rdata.DS{ds}, []rdata.DNSKEY{key})
	require.Equal(t, validator.Bogus, res)
	require.Error(t, err)
}

func TestResultString(t *testing.T) {
	t.Parallel()
	require.Equal(t, "secure", validator.Secure.String())
	require.Equal(t, "insecure", validator.Insecure.String())
	require.Equal(t, "bogus", validator.Bogus.String())
	require.Equal(t, "indeterminate", validator.Indeterminate.String())
}

func TestNTAStoreNames(t *testing.T) {
	t.Parallel()
	s := validator.NewNTAStore(wire.MustParseName("a.example"), wire.MustParseName("b.example"))
	names := s.Names()
	require.Len(t, names, 2)
}

func TestValidatorNTAsAccessor(t *testing.T) {
	t.Parallel()
	store := validator.NewNTAStore()
	v := validator.New(validator.Options{NTAs: store})
	require.Same(t, store, v.NTAs())
}
