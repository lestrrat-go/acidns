package dnssec

import (
	"crypto/subtle"
	"fmt"

	"github.com/lestrrat-go/acidns/dnssec/dnssecbb"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
)

// ErrSignatureMismatch is returned when an RRSIG fails verification.
var ErrSignatureMismatch = dnssecbb.ErrSignatureMismatch

// ErrUnsupportedAlgorithm is returned for DNSKEY/RRSIG/DS algorithm or
// digest type values this package does not implement.
var ErrUnsupportedAlgorithm = dnssecbb.ErrUnsupportedAlgorithm

// ErrInvalidKey is returned when a DNSKEY is structurally unfit for
// verification — wrong protocol field per RFC 4034 §2.1.2 or revoked
// per RFC 5011 §2.1.
var ErrInvalidKey = fmt.Errorf("dnssec: invalid DNSKEY")

// rejectedAlgorithms is the explicit deny-list. Even though the
// algorithm switch in Verify only handles modern algorithms, listing
// the deprecated ones here makes the rejection intentional and stops
// a future maintainer from silently weakening the validator by adding
// a switch case.
var rejectedAlgorithms = map[rdata.DNSSECAlgorithm]struct{}{
	rdata.AlgRSAMD5:           {},
	rdata.AlgDSA:              {},
	rdata.AlgRSASHA1:          {},
	rdata.AlgDSANSEC3SHA1:     {},
	rdata.AlgRSASHA1NSEC3SHA1: {},
}

// IsRejectedAlgorithm reports whether alg is on the explicit deny-list
// of deprecated DNSSEC algorithms. Callers that fetch an algorithm
// from the wire and want to fail closed before reaching Verify can use
// this directly.
func IsRejectedAlgorithm(alg rdata.DNSSECAlgorithm) bool {
	_, ok := rejectedAlgorithms[alg]
	return ok
}

// validateDNSKEY enforces the structural preconditions that RFC 4034
// §2.1.1 (Zone-Key bit), §2.1.2 (Protocol == 3) and RFC 5011 §2.1
// (Revoke flag) place on every DNSKEY used to validate.
func validateDNSKEY(key rdata.DNSKEY) error {
	if key.Protocol() != 3 {
		return fmt.Errorf("%w: protocol=%d (RFC 4034 §2.1.2 requires 3)",
			ErrInvalidKey, key.Protocol())
	}
	if key.Flags()&rdata.DNSKEYFlagRevoke != 0 {
		return fmt.Errorf("%w: REVOKE flag set (RFC 5011 §2.1)", ErrInvalidKey)
	}
	// RFC 4034 §2.1.1: "If bit 7 has value 0, then the DNSKEY record
	// holds some other type of DNS public key and MUST NOT be used to
	// verify RRSIGs that cover RRsets." A non-Zone DNSKEY (e.g. an
	// application key co-located in DNS) must never authenticate a
	// zone signature even if the owner publishes one with a matching
	// algorithm and key-tag.
	if key.Flags()&rdata.DNSKEYFlagZone == 0 {
		return fmt.Errorf("%w: Zone-Key flag clear (RFC 4034 §2.1.1)", ErrInvalidKey)
	}
	return nil
}

// Verify checks rrsig over set using key. It returns nil on success and a
// concrete error on any failure (algorithm mismatch, key tag mismatch,
// signature decode failure, or hash/signature mismatch).
func Verify(set []wire.Record, rrsig rdata.RRSIG, key rdata.DNSKEY) error {
	if err := validateDNSKEY(key); err != nil {
		return err
	}
	if IsRejectedAlgorithm(rrsig.Algorithm()) {
		return fmt.Errorf("%w: deprecated algorithm %d", ErrUnsupportedAlgorithm, rrsig.Algorithm())
	}
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
	case rdata.AlgRSASHA256, rdata.AlgRSASHA512:
		pub, err := dnssecbb.ParseRSAPublic(key.PublicKey())
		if err != nil {
			return err
		}
		return dnssecbb.VerifyRSA(uint8(rrsig.Algorithm()), pub, data, rrsig.Signature())
	case rdata.AlgECDSAP256SHA256:
		return dnssecbb.VerifyECDSAP256(data, key.PublicKey(), rrsig.Signature())
	case rdata.AlgECDSAP384SHA384:
		return dnssecbb.VerifyECDSAP384(data, key.PublicKey(), rrsig.Signature())
	case rdata.AlgED25519:
		return dnssecbb.VerifyEd25519(key.PublicKey(), data, rrsig.Signature())
	default:
		return fmt.Errorf("%w: algorithm %d", ErrUnsupportedAlgorithm, rrsig.Algorithm())
	}
}

// VerifyDS checks that ds matches the digest of (canonical owner ||
// dnskey rdata) for the supplied DNSKEY.
//
// SHA-1 (digest type 1) is rejected by default — RFC 8624 §3.3 marks
// SHA-1 DS digests as NOT RECOMMENDED, and SHA-1 collisions are within
// reach of motivated attackers; an attacker who can publish a forged
// DNSKEY whose SHA-1 DS digest collides with a legitimate one would
// otherwise pass this check. Callers that must still talk to legacy
// zones still publishing SHA-1 DS only — and accept the resulting
// security degradation — can opt in via [VerifyDSWithSHA1].
func VerifyDS(owner wire.Name, ds rdata.DS, key rdata.DNSKEY) error {
	return verifyDS(owner, ds, key, false)
}

// VerifyDSWithSHA1 is the same check as [VerifyDS] but accepts SHA-1
// (digest type 1) digests. RFC 8624 §3.3 marks SHA-1 DS as NOT
// RECOMMENDED and operators should retire SHA-1 DS records; this entry
// point exists solely so a validator can still authenticate a legacy
// zone during the rollover window from SHA-1 to SHA-256 or SHA-384 DS.
//
// Prefer [VerifyDS] for any new code. Pinning a chain through this
// function means accepting that a SHA-1 collision attack against the
// DS would let an attacker substitute a forged DNSKEY undetected.
func VerifyDSWithSHA1(owner wire.Name, ds rdata.DS, key rdata.DNSKEY) error {
	return verifyDS(owner, ds, key, true)
}

func verifyDS(owner wire.Name, ds rdata.DS, key rdata.DNSKEY, allowSHA1 bool) error {
	if err := validateDNSKEY(key); err != nil {
		return err
	}
	if !allowSHA1 && ds.DigestType() == rdata.DigestSHA1 {
		return fmt.Errorf("%w: SHA-1 DS digest refused by default (RFC 8624 §3.3) — use VerifyDSWithSHA1 to opt in", ErrUnsupportedAlgorithm)
	}
	if ds.KeyTag() != KeyTag(key) {
		return fmt.Errorf("%w: DS key tag mismatch", ErrSignatureMismatch)
	}
	if ds.Algorithm() != key.Algorithm() {
		return fmt.Errorf("%w: DS algorithm mismatch", ErrSignatureMismatch)
	}
	data := append([]byte(nil), owner.AppendWire(nil)...)
	data = append(data, dnskeyWire(key)...)

	sum, err := dnssecbb.Digest(uint8(ds.DigestType()), data)
	if err != nil {
		return fmt.Errorf("%w: DS digest type %d", ErrUnsupportedAlgorithm, ds.DigestType())
	}
	if subtle.ConstantTimeCompare(sum, ds.Digest()) != 1 {
		return ErrSignatureMismatch
	}
	return nil
}
