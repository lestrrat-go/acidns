package rdata

import (
	"github.com/lestrrat-go/acidns/dnsmsg/internal/wire"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
)

// NSEC3PARAM advertises the parameters used to compute NSEC3 hashes
// across a zone (RFC 5155 §4).
type NSEC3PARAM interface {
	RData
	HashAlgorithm() uint8
	Flags() uint8
	Iterations() uint16
	Salt() []byte
}

type nsec3param struct {
	alg, flags uint8
	iter       uint16
	salt       []byte
}

func (nsec3param) Type() rrtype.Type     { return rrtype.NSEC3PARAM }
func (n nsec3param) HashAlgorithm() uint8 { return n.alg }
func (n nsec3param) Flags() uint8         { return n.flags }
func (n nsec3param) Iterations() uint16   { return n.iter }
func (n nsec3param) Salt() []byte         { return n.salt }
func (n nsec3param) Pack(p *wire.Packer) {
	p.Uint8(n.alg)
	p.Uint8(n.flags)
	p.Uint16(n.iter)
	p.Uint8(uint8(len(n.salt)))
	p.Raw(n.salt)
}

// NewNSEC3PARAM returns an NSEC3PARAM rdata.
func NewNSEC3PARAM(alg, flags uint8, iter uint16, salt []byte) NSEC3PARAM {
	cp := append([]byte(nil), salt...)
	return nsec3param{alg: alg, flags: flags, iter: iter, salt: cp}
}

func unpackNSEC3PARAM(u *wire.Unpacker) (NSEC3PARAM, error) {
	alg, err := u.Uint8()
	if err != nil {
		return nil, err
	}
	flags, err := u.Uint8()
	if err != nil {
		return nil, err
	}
	iter, err := u.Uint16()
	if err != nil {
		return nil, err
	}
	saltLen, err := u.Uint8()
	if err != nil {
		return nil, err
	}
	salt, err := u.Bytes(int(saltLen))
	if err != nil {
		return nil, err
	}
	cp := append([]byte(nil), salt...)
	return nsec3param{alg: alg, flags: flags, iter: iter, salt: cp}, nil
}
