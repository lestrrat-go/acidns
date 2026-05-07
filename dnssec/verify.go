package dnssec

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SHA-1 still required by DS digest type 1.
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/dsig"
)

// ErrSignatureMismatch is returned when an RRSIG fails verification.
var ErrSignatureMismatch = errors.New("dnssec: signature mismatch")

// ErrUnsupportedAlgorithm is returned for DNSKEY/RRSIG/DS algorithm or
// digest type values this package does not implement.
var ErrUnsupportedAlgorithm = errors.New("dnssec: unsupported algorithm")

// Verify checks rrsig over set using key. It returns nil on success and a
// concrete error on any failure (algorithm mismatch, key tag mismatch,
// signature decode failure, or hash/signature mismatch).
func Verify(set []wire.Record, rrsig rdata.RRSIG, key rdata.DNSKEY) error {
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

	pub, dsigAlg, err := publicKeyFor(rrsig.Algorithm(), key.PublicKey())
	if err != nil {
		return err
	}
	if err := dsig.Verify(pub, dsigAlg, data, rrsig.Signature()); err != nil {
		return fmt.Errorf("%w: %w", ErrSignatureMismatch, err)
	}
	return nil
}

// publicKeyFor parses the wire-format DNSKEY public key bytes per the
// algorithm and returns the structured key plus the dsig algorithm name
// to verify with.
func publicKeyFor(alg rdata.DNSSECAlgorithm, raw []byte) (any, string, error) {
	switch alg {
	case rdata.AlgRSASHA256:
		pub, err := parseRSAPublic(raw)
		return pub, dsig.RSAPKCS1v15WithSHA256, err
	case rdata.AlgRSASHA512:
		pub, err := parseRSAPublic(raw)
		return pub, dsig.RSAPKCS1v15WithSHA512, err
	case rdata.AlgECDSAP256SHA256:
		pub, err := parseECDSAPublic(elliptic.P256(), 32, raw)
		return pub, dsig.ECDSAWithP256AndSHA256, err
	case rdata.AlgECDSAP384SHA384:
		pub, err := parseECDSAPublic(elliptic.P384(), 48, raw)
		return pub, dsig.ECDSAWithP384AndSHA384, err
	case rdata.AlgED25519:
		if len(raw) != ed25519.PublicKeySize {
			return nil, "", fmt.Errorf("%w: ed25519 pubkey wrong size", ErrSignatureMismatch)
		}
		return ed25519.PublicKey(raw), dsig.EdDSA, nil
	default:
		return nil, "", fmt.Errorf("%w: algorithm %d", ErrUnsupportedAlgorithm, alg)
	}
}

// parseRSAPublic decodes the RFC 3110 RSA public-key encoding: 1-byte
// exponent length OR 0 followed by 2-byte exponent length, then exponent,
// then modulus.
func parseRSAPublic(b []byte) (*rsa.PublicKey, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("dnssec: rsa pubkey too short")
	}
	var explen, off int
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

// parseECDSAPublic decodes the DNSSEC raw X||Y public-key encoding (RFC
// 6605 §4) into a *ecdsa.PublicKey. size is the per-component byte length
// (32 for P-256, 48 for P-384).
func parseECDSAPublic(curve elliptic.Curve, size int, raw []byte) (*ecdsa.PublicKey, error) {
	if len(raw) != 2*size {
		return nil, fmt.Errorf("%w: ecdsa pubkey wrong size", ErrSignatureMismatch)
	}
	x := new(big.Int).SetBytes(raw[:size])
	y := new(big.Int).SetBytes(raw[size:])
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// VerifyDS checks that ds matches the digest of (canonical owner ||
// dnskey rdata) for the supplied DNSKEY.
func VerifyDS(owner wire.Name, ds rdata.DS, key rdata.DNSKEY) error {
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
