package rdata

import (
	"fmt"

	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// HIPAlgorithm names the public-key algorithm used in a HIP record.
type HIPAlgorithm uint8

const (
	HIPAlgDSA   HIPAlgorithm = 1
	HIPAlgRSA   HIPAlgorithm = 2
	HIPAlgECDSA HIPAlgorithm = 3
)

// HIP is the Host Identity Protocol rdata (RFC 5205).
//
// Wire layout:
//
//	HIT length (1) | PK algorithm (1) | PK length (2)
//	HIT (HIT length) | Public key (PK length)
//	Rendezvous Server #1 ... #n (uncompressed domain names, fill remainder)
type HIP interface {
	RData
	Algorithm() HIPAlgorithm
	HIT() []byte
	PublicKey() []byte
	RendezvousServers() []wirebb.Name
}

type hip struct {
	alg    HIPAlgorithm
	hit    []byte
	pubkey []byte
	rvs    []wirebb.Name
}

func (hip) Type() rrtype.Type                  { return rrtype.HIP }
func (h hip) Algorithm() HIPAlgorithm          { return h.alg }
func (h hip) HIT() []byte                      { return h.hit }
func (h hip) PublicKey() []byte                { return h.pubkey }
func (h hip) RendezvousServers() []wirebb.Name { return h.rvs }
func (h hip) Pack(p *wirebb.Packer) {
	p.Uint8(uint8(len(h.hit)))
	p.Uint8(uint8(h.alg))
	p.Uint16(uint16(len(h.pubkey)))
	p.Raw(h.hit)
	p.Raw(h.pubkey)
	for _, rv := range h.rvs {
		// RFC 5205 §5: rendezvous servers are uncompressed.
		p.NameUncompressed(rv)
	}
}

// NewHIP returns a HIP rdata. HIT length must fit in a uint8; public key
// length must fit in a uint16.
func NewHIP(alg HIPAlgorithm, hit, pubkey []byte, rvs ...wirebb.Name) (HIP, error) {
	if len(hit) > 0xff {
		return nil, fmt.Errorf("%w: HIP HIT length %d exceeds 255", ErrInvalidRData, len(hit))
	}
	if len(pubkey) > 0xffff {
		return nil, fmt.Errorf("%w: HIP public key length %d exceeds 65535", ErrInvalidRData, len(pubkey))
	}
	hcp := make([]byte, len(hit))
	copy(hcp, hit)
	pcp := make([]byte, len(pubkey))
	copy(pcp, pubkey)
	rcp := make([]wirebb.Name, len(rvs))
	copy(rcp, rvs)
	return hip{alg: alg, hit: hcp, pubkey: pcp, rvs: rcp}, nil
}

func unpackHIP(u *wirebb.Unpacker, rdlen int) (HIP, error) {
	end := u.Off() + rdlen
	hitLen, err := u.Uint8()
	if err != nil {
		return nil, err
	}
	alg, err := u.Uint8()
	if err != nil {
		return nil, err
	}
	pkLen, err := u.Uint16()
	if err != nil {
		return nil, err
	}
	hit, err := u.Bytes(int(hitLen))
	if err != nil {
		return nil, err
	}
	pk, err := u.Bytes(int(pkLen))
	if err != nil {
		return nil, err
	}
	hcp := make([]byte, len(hit))
	copy(hcp, hit)
	pcp := make([]byte, len(pk))
	copy(pcp, pk)
	var rvs []wirebb.Name
	for u.Off() < end {
		n, err := u.Name()
		if err != nil {
			return nil, err
		}
		rvs = append(rvs, n)
	}
	return hip{alg: HIPAlgorithm(alg), hit: hcp, pubkey: pcp, rvs: rvs}, nil
}
