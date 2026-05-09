package rdata

import (
	"slices"

	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// NSEC3PARAM advertises the parameters used to compute NSEC3 hashes
// across a zone (RFC 5155 §4).
type NSEC3PARAM struct {
	alg, flags uint8
	iter       uint16
	salt       []byte
}

func (NSEC3PARAM) Type() rrtype.Type      { return rrtype.NSEC3PARAM }
func (NSEC3PARAM) typedRData()            {}
func (n NSEC3PARAM) HashAlgorithm() uint8 { return n.alg }
func (n NSEC3PARAM) Flags() uint8         { return n.flags }
func (n NSEC3PARAM) Iterations() uint16   { return n.iter }
func (n NSEC3PARAM) Salt() []byte         { return slices.Clone(n.salt) }
func (n NSEC3PARAM) Pack(p *wirebb.Packer) {
	p.Uint8(n.alg)
	p.Uint8(n.flags)
	p.Uint16(n.iter)
	p.Uint8(uint8(len(n.salt)))
	p.Raw(n.salt)
}

// NewNSEC3PARAM returns an NSEC3PARAM rdata.
func NewNSEC3PARAM(alg, flags uint8, iter uint16, salt []byte) NSEC3PARAM {
	cp := append([]byte(nil), salt...)
	return NSEC3PARAM{alg: alg, flags: flags, iter: iter, salt: cp}
}

func unpackNSEC3PARAM(u *wirebb.Unpacker) (NSEC3PARAM, error) {
	var zero NSEC3PARAM
	alg, err := u.Uint8()
	if err != nil {
		return zero, err
	}
	flags, err := u.Uint8()
	if err != nil {
		return zero, err
	}
	iter, err := u.Uint16()
	if err != nil {
		return zero, err
	}
	saltLen, err := u.Uint8()
	if err != nil {
		return zero, err
	}
	salt, err := u.Bytes(int(saltLen))
	if err != nil {
		return zero, err
	}
	cp := append([]byte(nil), salt...)
	return NSEC3PARAM{alg: alg, flags: flags, iter: iter, salt: cp}, nil
}
