package dnssec

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SHA-1 still required by DS digest type 1.
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"math/big"

	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsname"
)

// ErrSignatureMismatch is returned when an RRSIG fails verification.
var ErrSignatureMismatch = errors.New("dnssec: signature mismatch")

// ErrUnsupportedAlgorithm is returned for DNSKEY/RRSIG/DS algorithm or
// digest type values this package does not implement.
var ErrUnsupportedAlgorithm = errors.New("dnssec: unsupported algorithm")

// Verify checks rrsig over set using key. It returns nil on success and a
// concrete error on any failure (algorithm mismatch, key tag mismatch,
// signature decode failure, or hash/signature mismatch).
func Verify(set []dnsmsg.Record, rrsig rdata.RRSIG, key rdata.DNSKEY) error {
	if rrsig.Algorithm() != key.Algorithm() {
		return fmt.Errorf("%w: rrsig alg %d vs dnskey alg %d",
			ErrSignatureMismatch, rrsig.Algorithm(), key.Algorithm())
	}
	if rrsig.KeyTag() != KeyTag(key) {
		return fmt.Errorf("%w: key tag mismatch", ErrSignatureMismatch)
	}
	data, err := signedData(set, rrsig)
	if err != nil {
		return err
	}

	switch rrsig.Algorithm() {
	case rdata.AlgRSASHA256:
		pub, err := parseRSAPublic(key.PublicKey())
		if err != nil {
			return err
		}
		h := sha256.Sum256(data)
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], rrsig.Signature()); err != nil {
			return fmt.Errorf("%w: %w", ErrSignatureMismatch, err)
		}
		return nil
	case rdata.AlgRSASHA512:
		pub, err := parseRSAPublic(key.PublicKey())
		if err != nil {
			return err
		}
		h := sha512.Sum512(data)
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA512, h[:], rrsig.Signature()); err != nil {
			return fmt.Errorf("%w: %w", ErrSignatureMismatch, err)
		}
		return nil
	case rdata.AlgECDSAP256SHA256:
		return verifyECDSA(elliptic.P256(), 32, sha256.New, data, key.PublicKey(), rrsig.Signature())
	case rdata.AlgECDSAP384SHA384:
		return verifyECDSA(elliptic.P384(), 48, sha512.New384, data, key.PublicKey(), rrsig.Signature())
	case rdata.AlgED25519:
		if len(key.PublicKey()) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: ed25519 pubkey wrong size", ErrSignatureMismatch)
		}
		if !ed25519.Verify(ed25519.PublicKey(key.PublicKey()), data, rrsig.Signature()) {
			return ErrSignatureMismatch
		}
		return nil
	default:
		return fmt.Errorf("%w: algorithm %d", ErrUnsupportedAlgorithm, rrsig.Algorithm())
	}
}

func parseRSAPublic(b []byte) (*rsa.PublicKey, error) {
	// RFC 3110: pubkey = 1-byte exponent length OR 0 followed by 2-byte
	// exponent length, then exponent, then modulus.
	if len(b) < 1 {
		return nil, fmt.Errorf("dnssec: rsa pubkey too short")
	}
	var explen int
	var off int
	if b[0] == 0 {
		if len(b) < 3 {
			return nil, fmt.Errorf("dnssec: rsa pubkey truncated")
		}
		explen = int(b[1])<<8 | int(b[2])
		off = 3
	} else {
		explen = int(b[0])
		off = 1
	}
	if len(b) < off+explen {
		return nil, fmt.Errorf("dnssec: rsa pubkey truncated exponent")
	}
	e := new(big.Int).SetBytes(b[off : off+explen])
	if !e.IsInt64() {
		return nil, fmt.Errorf("dnssec: rsa exponent too large")
	}
	mod := new(big.Int).SetBytes(b[off+explen:])
	return &rsa.PublicKey{N: mod, E: int(e.Int64())}, nil
}

func verifyECDSA(curve elliptic.Curve, size int, h func() hash.Hash, data, pub, sig []byte) error {
	if len(pub) != 2*size {
		return fmt.Errorf("%w: ecdsa pubkey wrong size", ErrSignatureMismatch)
	}
	if len(sig) != 2*size {
		return fmt.Errorf("%w: ecdsa signature wrong size", ErrSignatureMismatch)
	}
	x := new(big.Int).SetBytes(pub[:size])
	y := new(big.Int).SetBytes(pub[size:])
	r := new(big.Int).SetBytes(sig[:size])
	s := new(big.Int).SetBytes(sig[size:])
	pubKey := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	hh := h()
	hh.Write(data)
	if !ecdsa.Verify(pubKey, hh.Sum(nil), r, s) {
		return ErrSignatureMismatch
	}
	return nil
}

// VerifyDS checks that ds matches the digest of (canonical owner ||
// dnskey rdata) for the supplied DNSKEY.
func VerifyDS(owner dnsname.Name, ds rdata.DS, key rdata.DNSKEY) error {
	if ds.KeyTag() != KeyTag(key) {
		return fmt.Errorf("%w: DS key tag mismatch", ErrSignatureMismatch)
	}
	if ds.Algorithm() != key.Algorithm() {
		return fmt.Errorf("%w: DS algorithm mismatch", ErrSignatureMismatch)
	}
	data := append([]byte(nil), owner.AppendWire(nil)...)
	data = append(data, dnskeyWire(key)...)

	var sum []byte
	switch ds.DigestType() {
	case rdata.DigestSHA1:
		h := sha1.Sum(data) //nolint:gosec
		sum = h[:]
	case rdata.DigestSHA256:
		h := sha256.Sum256(data)
		sum = h[:]
	case rdata.DigestSHA384:
		h := sha512.Sum384(data)
		sum = h[:]
	default:
		return fmt.Errorf("%w: DS digest type %d", ErrUnsupportedAlgorithm, ds.DigestType())
	}
	if !bytesEqual(sum, ds.Digest()) {
		return ErrSignatureMismatch
	}
	return nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
