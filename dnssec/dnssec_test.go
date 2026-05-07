package dnssec_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"math/big"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnssec"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// signRRSIG builds an RRSIG over set using sign and returns the signed
// (cleartext) payload bytes alongside the resulting RRSIG.
type signFn func(payload []byte) ([]byte, error)

func makeRRSIG(t *testing.T, set []wire.Record, alg rdata.DNSSECAlgorithm,
	keyTag uint16, signer wire.Name, sign signFn) rdata.RRSIG {
	t.Helper()
	if len(set) == 0 {
		t.Fatal("empty set")
	}
	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	inc := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	origTTL := set[0].TTL()
	rrsig := rdata.NewRRSIG(set[0].Type(), alg, uint8(set[0].Name().NumLabels()),
		origTTL, exp, inc, keyTag, signer, nil)

	payload, err := dnssec.SignedDataForTest(set, rrsig)
	require.NoError(t, err)
	sig, err := sign(payload)
	require.NoError(t, err)
	return rdata.NewRRSIG(set[0].Type(), alg, uint8(set[0].Name().NumLabels()),
		origTTL, exp, inc, keyTag, signer, sig)
}

func mkARRSet(name string, ip string) []wire.Record {
	n := wire.MustParseName(name)
	r := wire.NewRecord(n, time.Hour, rdata.NewA(netip.MustParseAddr(ip)))
	return []wire.Record{r}
}

func TestVerifyECDSAP256(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	encPK, err2 := priv.PublicKey.Bytes()
	require.NoError(t, err2)
	pub := encPK[1:]
	key := rdata.NewDNSKEY(257, 3, rdata.AlgECDSAP256SHA256, pub)

	signer := wire.MustParseName("example.com")
	sign := func(payload []byte) ([]byte, error) {
		h := sha256.Sum256(payload)
		r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
		if err != nil {
			return nil, err
		}
		out := make([]byte, 64)
		r.FillBytes(out[:32])
		s.FillBytes(out[32:])
		return out, nil
	}

	set := mkARRSet("www.example.com", "192.0.2.1")
	rrsig := makeRRSIG(t, set, rdata.AlgECDSAP256SHA256, dnssec.KeyTag(key), signer, sign)
	require.NoError(t, dnssec.Verify(set, rrsig, key))

	// Tamper: a different IP must fail verification.
	bad := mkARRSet("www.example.com", "192.0.2.99")
	require.ErrorIs(t, dnssec.Verify(bad, rrsig, key), dnssec.ErrSignatureMismatch)
}

func TestVerifyECDSAP384(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	encPK, err2 := priv.PublicKey.Bytes()
	require.NoError(t, err2)
	pub := encPK[1:]
	key := rdata.NewDNSKEY(257, 3, rdata.AlgECDSAP384SHA384, pub)

	signer := wire.MustParseName("example.com")
	sign := func(payload []byte) ([]byte, error) {
		h := sha512.Sum384(payload)
		r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
		if err != nil {
			return nil, err
		}
		out := make([]byte, 96)
		r.FillBytes(out[:48])
		s.FillBytes(out[48:])
		return out, nil
	}

	set := mkARRSet("www.example.com", "192.0.2.2")
	rrsig := makeRRSIG(t, set, rdata.AlgECDSAP384SHA384, dnssec.KeyTag(key), signer, sign)
	require.NoError(t, dnssec.Verify(set, rrsig, key))
}

func TestVerifyED25519(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	key := rdata.NewDNSKEY(257, 3, rdata.AlgED25519, pub)

	signer := wire.MustParseName("example.com")
	sign := func(payload []byte) ([]byte, error) {
		return ed25519.Sign(priv, payload), nil
	}

	set := mkARRSet("www.example.com", "192.0.2.3")
	rrsig := makeRRSIG(t, set, rdata.AlgED25519, dnssec.KeyTag(key), signer, sign)
	require.NoError(t, dnssec.Verify(set, rrsig, key))
}

func TestVerifyRSASHA256(t *testing.T) {
	t.Parallel()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Pubkey wire: 1-byte exponent length, exponent, modulus.
	expBytes := big.NewInt(int64(priv.E)).Bytes()
	pubWire := make([]byte, 0, 1+len(expBytes)+len(priv.N.Bytes()))
	pubWire = append(pubWire, byte(len(expBytes)))
	pubWire = append(pubWire, expBytes...)
	pubWire = append(pubWire, priv.N.Bytes()...)
	key := rdata.NewDNSKEY(257, 3, rdata.AlgRSASHA256, pubWire)

	signer := wire.MustParseName("example.com")
	sign := func(payload []byte) ([]byte, error) {
		h := sha256.Sum256(payload)
		return rsa.SignPKCS1v15(rand.Reader, priv, sha256Hasher, h[:])
	}

	set := mkARRSet("www.example.com", "192.0.2.4")
	rrsig := makeRRSIG(t, set, rdata.AlgRSASHA256, dnssec.KeyTag(key), signer, sign)
	require.NoError(t, dnssec.Verify(set, rrsig, key))
}

// sha256Hasher is the crypto.Hash needed by rsa.SignPKCS1v15.
const sha256Hasher = 5 // crypto.SHA256

func TestKeyTagKnownVector(t *testing.T) {
	t.Parallel()
	// RFC 4034 §B.1 example: a 64-byte random-ish DNSKEY rdata produces a
	// known 16-bit sum. We use a generated pubkey here and assert KeyTag
	// equals the manual computation, which exercises the algorithm even
	// without a fixed external vector.
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i)
	}
	key := rdata.NewDNSKEY(257, 3, rdata.AlgED25519, pub)
	tag := dnssec.KeyTag(key)
	require.NotZero(t, tag)

	// Compute by hand and compare.
	wire := []byte{0x01, 0x01, 3, byte(rdata.AlgED25519)}
	wire = append(wire, pub...)
	var sum uint32
	for i, b := range wire {
		if i%2 == 0 {
			sum += uint32(b) << 8
		} else {
			sum += uint32(b)
		}
	}
	sum += sum >> 16 & 0xffff
	require.Equal(t, uint16(sum), tag)
}

func TestVerifyDS(t *testing.T) {
	t.Parallel()
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(0xcc ^ i)
	}
	key := rdata.NewDNSKEY(257, 3, rdata.AlgED25519, pub)
	owner := wire.MustParseName("example.com")

	// Build the digest by hand: sha256(owner | dnskey rdata)
	var data []byte
	data = append(data, owner.AppendWire(nil)...)
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint16(hdr[0:], key.Flags())
	hdr[2] = key.Protocol()
	hdr[3] = uint8(key.Algorithm())
	data = append(data, hdr...)
	data = append(data, pub...)
	digest := sha256.Sum256(data)

	ds := rdata.NewDS(dnssec.KeyTag(key), rdata.AlgED25519, rdata.DigestSHA256, digest[:])
	require.NoError(t, dnssec.VerifyDS(owner, ds, key))

	// Tamper digest → mismatch.
	bad := append([]byte(nil), digest[:]...)
	bad[0] ^= 0xff
	dsBad := rdata.NewDS(dnssec.KeyTag(key), rdata.AlgED25519, rdata.DigestSHA256, bad)
	require.ErrorIs(t, dnssec.VerifyDS(owner, dsBad, key), dnssec.ErrSignatureMismatch)
}

func TestUnsupportedAlgorithm(t *testing.T) {
	t.Parallel()
	pub := make([]byte, 32)
	key := rdata.NewDNSKEY(257, 3, rdata.DNSSECAlgorithm(99), pub)
	signer := wire.MustParseName("example.com")
	rrsig := rdata.NewRRSIG(rrtype.A, rdata.DNSSECAlgorithm(99), 3,
		time.Hour, time.Now().Add(time.Hour), time.Now().Add(-time.Hour),
		dnssec.KeyTag(key), signer, []byte{0xaa})
	set := mkARRSet("x.example.com", "192.0.2.7")
	err := dnssec.Verify(set, rrsig, key)
	require.ErrorIs(t, err, dnssec.ErrUnsupportedAlgorithm)
}
