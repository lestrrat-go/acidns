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
type HIP struct {
	alg    HIPAlgorithm
	hit    []byte
	pubkey []byte
	rvs    []wirebb.Name
}

func (HIP) Type() rrtype.Type                  { return rrtype.HIP }
func (HIP) typedRData()                        {}
func (h HIP) Algorithm() HIPAlgorithm          { return h.alg }
func (h HIP) HIT() []byte                      { return h.hit }
func (h HIP) PublicKey() []byte                { return h.pubkey }
func (h HIP) RendezvousServers() []wirebb.Name { return h.rvs }
func (h HIP) Pack(p *wirebb.Packer) {
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
	var zero HIP
	if len(hit) > 0xff {
		return zero, fmt.Errorf("%w: HIP HIT length %d exceeds 255", ErrInvalidRData, len(hit))
	}
	if len(pubkey) > 0xffff {
		return zero, fmt.Errorf("%w: HIP public key length %d exceeds 65535", ErrInvalidRData, len(pubkey))
	}
	hcp := make([]byte, len(hit))
	copy(hcp, hit)
	pcp := make([]byte, len(pubkey))
	copy(pcp, pubkey)
	rcp := make([]wirebb.Name, len(rvs))
	copy(rcp, rvs)
	return HIP{alg: alg, hit: hcp, pubkey: pcp, rvs: rcp}, nil
}

func unpackHIP(u *wirebb.Unpacker, rdlen int) (HIP, error) {
	var zero HIP
	end := u.Off() + rdlen
	hitLen, err := u.Uint8()
	if err != nil {
		return zero, err
	}
	alg, err := u.Uint8()
	if err != nil {
		return zero, err
	}
	pkLen, err := u.Uint16()
	if err != nil {
		return zero, err
	}
	hit, err := u.Bytes(int(hitLen))
	if err != nil {
		return zero, err
	}
	pk, err := u.Bytes(int(pkLen))
	if err != nil {
		return zero, err
	}
	hcp := make([]byte, len(hit))
	copy(hcp, hit)
	pcp := make([]byte, len(pk))
	copy(pcp, pk)
	var rvs []wirebb.Name
	for u.Off() < end {
		n, err := u.Name()
		if err != nil {
			return zero, err
		}
		rvs = append(rvs, n)
	}
	return HIP{alg: HIPAlgorithm(alg), hit: hcp, pubkey: pcp, rvs: rvs}, nil
}
