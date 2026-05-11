// Package spki computes the SHA-256 SubjectPublicKeyInfo (SPKI) hash
// used by RFC 7858 §4.2 DoT certificate pinning and RFC 9250 DoQ
// certificate pinning. The hash covers the DER-encoded SPKI structure
// — public key algorithm identifier and public key bytes — which is
// stable across leaf-cert reissuance as long as the underlying key
// is rotated.
package spki

import (
	"crypto/sha256"
	"crypto/x509"
)

// HashSize is the length in bytes of an SPKI pin (SHA-256 output).
const HashSize = sha256.Size

// Hash returns the SHA-256 hash of cert's SubjectPublicKeyInfo. The
// returned value is what RFC 7858 §4.2 calls a "SPKI Fingerprint" and
// what operators publish as the pin set for a DoT or DoQ resolver.
func Hash(cert *x509.Certificate) [HashSize]byte {
	return sha256.Sum256(cert.RawSubjectPublicKeyInfo)
}
