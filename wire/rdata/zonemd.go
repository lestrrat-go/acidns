package rdata

import (
	"fmt"

	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// ZONEMDScheme identifies the digest scheme used by a ZONEMD record.
type ZONEMDScheme uint8

const (
	ZONEMDSchemeSimple ZONEMDScheme = 1 // RFC 8976 §4
)

// ZONEMDHashAlgorithm identifies the digest algorithm used by a ZONEMD record.
type ZONEMDHashAlgorithm uint8

const (
	ZONEMDHashSHA384 ZONEMDHashAlgorithm = 1
	ZONEMDHashSHA512 ZONEMDHashAlgorithm = 2
)

// ZONEMD is the Message Digest for DNS Zones rdata (RFC 8976).
type ZONEMD struct {
	serial uint32
	scheme ZONEMDScheme
	hash   ZONEMDHashAlgorithm
	digest []byte
}

func (ZONEMD) Type() rrtype.Type                    { return rrtype.ZONEMD }
func (ZONEMD) typedRData()                          {}
func (z ZONEMD) Serial() uint32                     { return z.serial }
func (z ZONEMD) Scheme() ZONEMDScheme               { return z.scheme }
func (z ZONEMD) HashAlgorithm() ZONEMDHashAlgorithm { return z.hash }
func (z ZONEMD) Digest() []byte                     { return z.digest }
func (z ZONEMD) Pack(p *wirebb.Packer) {
	p.Uint32(z.serial)
	p.Uint8(uint8(z.scheme))
	p.Uint8(uint8(z.hash))
	p.Raw(z.digest)
}

// NewZONEMD returns a ZONEMD rdata. For known hash algorithms the
// digest length is validated against RFC 8976 §4 (SHA-384 → 48 bytes,
// SHA-512 → 64 bytes). Unknown algorithms pass through unvalidated:
// RFC 8976 §3 directs validators to ignore unknown algorithms rather
// than reject the record outright, and acidns preserves that
// information for inspection.
func NewZONEMD(serial uint32, scheme ZONEMDScheme, hash ZONEMDHashAlgorithm, digest []byte) (ZONEMD, error) {
	if err := validateZONEMDDigestLength(hash, len(digest)); err != nil {
		return ZONEMD{}, err
	}
	cp := make([]byte, len(digest))
	copy(cp, digest)
	return ZONEMD{serial: serial, scheme: scheme, hash: hash, digest: cp}, nil
}

// validateZONEMDDigestLength enforces RFC 8976 §4 fixed digest lengths
// for the registered hash algorithms. Returns nil for unknown
// algorithms (RFC 8976 §3 "ignore unknown") so that wire-decoded
// records with unfamiliar Hash values survive the parse step and can
// be inspected by callers.
func validateZONEMDDigestLength(hash ZONEMDHashAlgorithm, n int) error {
	var want int
	switch hash {
	case ZONEMDHashSHA384:
		want = 48
	case ZONEMDHashSHA512:
		want = 64
	default:
		return nil
	}
	if n != want {
		return fmt.Errorf("%w: ZONEMD hash %d digest len=%d, RFC 8976 §4 mandates %d", ErrInvalidRData, hash, n, want)
	}
	return nil
}

func unpackZONEMD(u *wirebb.Unpacker, rdlen int) (ZONEMD, error) {
	var zero ZONEMD
	if rdlen < 6 {
		return zero, fmt.Errorf("%w: ZONEMD rdlen=%d, want >=6", ErrInvalidRData, rdlen)
	}
	serial, err := u.Uint32()
	if err != nil {
		return zero, err
	}
	scheme, err := u.Uint8()
	if err != nil {
		return zero, err
	}
	hash, err := u.Uint8()
	if err != nil {
		return zero, err
	}
	digest, err := u.Bytes(rdlen - 6)
	if err != nil {
		return zero, err
	}
	if err := validateZONEMDDigestLength(ZONEMDHashAlgorithm(hash), len(digest)); err != nil {
		return zero, err
	}
	cp := make([]byte, len(digest))
	copy(cp, digest)
	return ZONEMD{serial: serial, scheme: ZONEMDScheme(scheme), hash: ZONEMDHashAlgorithm(hash), digest: cp}, nil
}
