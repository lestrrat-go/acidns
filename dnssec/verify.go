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
func VerifyDS(owner wire.Name, ds rdata.DS, key rdata.DNSKEY) error {
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
