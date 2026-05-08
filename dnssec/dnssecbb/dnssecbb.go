// Package dnssecbb is the low-level DNSSEC primitive layer ("building
// blocks") for [github.com/lestrrat-go/acidns/dnssec]. It exposes the pure
// cryptographic operations used to verify DNSSEC signatures and DS digests
// without requiring callers to construct wire-level RR records.
//
// Use this package when you have already-canonicalised signed-data bytes
// and a public key, and want to verify a signature directly. The parent
// dnssec package wraps these primitives with the [dnssec.Verify] /
// [dnssec.VerifyDS] / [dnssec.SignedData] / [dnssec.KeyTag] API that
// operates on [wire.Record] and [rdata] types.
package dnssecbb

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
)

// ErrSignatureMismatch is returned when a signature fails verification.
var ErrSignatureMismatch = errors.New("dnssecbb: signature mismatch")

// ErrUnsupportedAlgorithm is returned for algorithm or digest type values
// this package does not implement.
var ErrUnsupportedAlgorithm = errors.New("dnssecbb: unsupported algorithm")

// Algorithm IDs from the IANA DNS Security Algorithm Numbers registry
// (see RFC 8624 §3.1 for current implementation requirements).
const (
	AlgRSASHA256       uint8 = 8
	AlgRSASHA512       uint8 = 10
	AlgECDSAP256SHA256 uint8 = 13
	AlgECDSAP384SHA384 uint8 = 14
	AlgED25519         uint8 = 15
)

// Digest type IDs from the IANA DS RR Digest Algorithm registry.
const (
	DigestSHA1   uint8 = 1
	DigestSHA256 uint8 = 2
	DigestSHA384 uint8 = 4
)

// ParseRSAPublic decodes the RFC 3110 public-key encoding (1-byte
// exponent length, or a leading 0 + 2-byte exponent length, then exponent
// bytes, then modulus bytes) into a [*rsa.PublicKey].
func ParseRSAPublic(b []byte) (*rsa.PublicKey, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("dnssecbb: rsa pubkey too short")
	}
	var explen int
	var off int
	if b[0] == 0 {
		if len(b) < 3 {
			return nil, fmt.Errorf("dnssecbb: rsa pubkey truncated")
		}
		explen = int(b[1])<<8 | int(b[2])
		off = 3
	} else {
		explen = int(b[0])
		off = 1
	}
	if len(b) < off+explen {
		return nil, fmt.Errorf("dnssecbb: rsa pubkey truncated exponent")
	}
	e := new(big.Int).SetBytes(b[off : off+explen])
	if !e.IsInt64() {
		return nil, fmt.Errorf("dnssecbb: rsa exponent too large")
	}
	mod := new(big.Int).SetBytes(b[off+explen:])
	return &rsa.PublicKey{N: mod, E: int(e.Int64())}, nil
}

// VerifyRSA checks an RSA-PKCS1v15 signature over data using pub. alg
// selects the hash (SHA-256 for [AlgRSASHA256], SHA-512 for [AlgRSASHA512]).
func VerifyRSA(alg uint8, pub *rsa.PublicKey, data, sig []byte) error {
	switch alg {
	case AlgRSASHA256:
		h := sha256.Sum256(data)
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig); err != nil {
			return fmt.Errorf("%w: %w", ErrSignatureMismatch, err)
		}
		return nil
	case AlgRSASHA512:
		h := sha512.Sum512(data)
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA512, h[:], sig); err != nil {
			return fmt.Errorf("%w: %w", ErrSignatureMismatch, err)
		}
		return nil
	default:
		return fmt.Errorf("%w: rsa alg %d", ErrUnsupportedAlgorithm, alg)
	}
}

// VerifyECDSA checks an ECDSA(R || S) signature over data using a raw
// (X || Y) public-key encoding. size is the per-component byte length
// (32 for P-256, 48 for P-384). hashFn is the hash to apply to data.
func VerifyECDSA(curve elliptic.Curve, size int, hashFn func() hash.Hash, data, pub, sig []byte) error {
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
	hh := hashFn()
	hh.Write(data)
	if !ecdsa.Verify(pubKey, hh.Sum(nil), r, s) {
		return ErrSignatureMismatch
	}
	return nil
}

// VerifyECDSAP256 is shorthand for [VerifyECDSA] with P-256 + SHA-256
// (DNSSEC algorithm 13).
func VerifyECDSAP256(data, pub, sig []byte) error {
	return VerifyECDSA(elliptic.P256(), 32, sha256.New, data, pub, sig)
}

// VerifyECDSAP384 is shorthand for [VerifyECDSA] with P-384 + SHA-384
// (DNSSEC algorithm 14).
func VerifyECDSAP384(data, pub, sig []byte) error {
	return VerifyECDSA(elliptic.P384(), 48, sha512.New384, data, pub, sig)
}

// VerifyEd25519 checks an Ed25519 signature over data using pub
// (DNSSEC algorithm 15). pub must be exactly [ed25519.PublicKeySize].
func VerifyEd25519(pub, data, sig []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: ed25519 pubkey wrong size", ErrSignatureMismatch)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), data, sig) {
		return ErrSignatureMismatch
	}
	return nil
}

// Digest applies the digest type identified by dt (see [DigestSHA1] /
// [DigestSHA256] / [DigestSHA384]) to data and returns the result.
func Digest(dt uint8, data []byte) ([]byte, error) {
	switch dt {
	case DigestSHA1:
		h := sha1.Sum(data) //nolint:gosec
		return h[:], nil
	case DigestSHA256:
		h := sha256.Sum256(data)
		return h[:], nil
	case DigestSHA384:
		h := sha512.Sum384(data)
		return h[:], nil
	default:
		return nil, fmt.Errorf("%w: digest type %d", ErrUnsupportedAlgorithm, dt)
	}
}
