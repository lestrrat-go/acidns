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
type ZONEMD interface {
	RData
	Serial() uint32
	Scheme() ZONEMDScheme
	HashAlgorithm() ZONEMDHashAlgorithm
	Digest() []byte
}

type zonemd struct {
	serial uint32
	scheme ZONEMDScheme
	hash   ZONEMDHashAlgorithm
	digest []byte
}

func (zonemd) Type() rrtype.Type                    { return rrtype.ZONEMD }
func (z zonemd) Serial() uint32                     { return z.serial }
func (z zonemd) Scheme() ZONEMDScheme               { return z.scheme }
func (z zonemd) HashAlgorithm() ZONEMDHashAlgorithm { return z.hash }
func (z zonemd) Digest() []byte                     { return z.digest }
func (z zonemd) Pack(p *wirebb.Packer) {
	p.Uint32(z.serial)
	p.Uint8(uint8(z.scheme))
	p.Uint8(uint8(z.hash))
	p.Raw(z.digest)
}

// NewZONEMD returns a ZONEMD rdata.
func NewZONEMD(serial uint32, scheme ZONEMDScheme, hash ZONEMDHashAlgorithm, digest []byte) ZONEMD {
	cp := make([]byte, len(digest))
	copy(cp, digest)
	return zonemd{serial: serial, scheme: scheme, hash: hash, digest: cp}
}

func unpackZONEMD(u *wirebb.Unpacker, rdlen int) (ZONEMD, error) {
	if rdlen < 6 {
		return nil, fmt.Errorf("%w: ZONEMD rdlen=%d, want >=6", ErrInvalidRData, rdlen)
	}
	serial, err := u.Uint32()
	if err != nil {
		return nil, err
	}
	scheme, err := u.Uint8()
	if err != nil {
		return nil, err
	}
	hash, err := u.Uint8()
	if err != nil {
		return nil, err
	}
	digest, err := u.Bytes(rdlen - 6)
	if err != nil {
		return nil, err
	}
	cp := make([]byte, len(digest))
	copy(cp, digest)
	return zonemd{serial: serial, scheme: ZONEMDScheme(scheme), hash: ZONEMDHashAlgorithm(hash), digest: cp}, nil
}
