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

// NewZONEMD returns a ZONEMD rdata.
func NewZONEMD(serial uint32, scheme ZONEMDScheme, hash ZONEMDHashAlgorithm, digest []byte) ZONEMD {
	cp := make([]byte, len(digest))
	copy(cp, digest)
	return ZONEMD{serial: serial, scheme: scheme, hash: hash, digest: cp}
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
	cp := make([]byte, len(digest))
	copy(cp, digest)
	return ZONEMD{serial: serial, scheme: ZONEMDScheme(scheme), hash: ZONEMDHashAlgorithm(hash), digest: cp}, nil
}
