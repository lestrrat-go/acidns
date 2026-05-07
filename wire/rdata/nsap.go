package rdata

import (
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// NSAP is the Network Service Access Point address rdata (RFC 1706, formerly
// RFC 1348). The wire format is the raw NSAP address bytes, no length prefix.
type NSAP interface {
	RData
	Address() []byte
}

type nsap struct{ addr []byte }

func (nsap) Type() rrtype.Type       { return rrtype.NSAP }
func (n nsap) Address() []byte       { return n.addr }
func (n nsap) Pack(p *wirebb.Packer) { p.Raw(n.addr) }

// NewNSAP returns an NSAP rdata. The address bytes are copied.
func NewNSAP(addr []byte) NSAP {
	cp := make([]byte, len(addr))
	copy(cp, addr)
	return nsap{addr: cp}
}

func unpackNSAP(u *wirebb.Unpacker, rdlen int) (NSAP, error) {
	b, err := u.Bytes(rdlen)
	if err != nil {
		return nil, err
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	return nsap{addr: cp}, nil
}

// NSAPPTR is the NSAP-PTR rdata (RFC 1706 §6).
type NSAPPTR interface {
	RData
	Owner() wirebb.Name
}

type nsapptr struct{ owner wirebb.Name }

func (nsapptr) Type() rrtype.Type       { return rrtype.NSAPPTR }
func (n nsapptr) Owner() wirebb.Name    { return n.owner }
func (n nsapptr) Pack(p *wirebb.Packer) { p.Name(n.owner) }

// NewNSAPPTR returns an NSAP-PTR rdata.
func NewNSAPPTR(owner wirebb.Name) NSAPPTR { return nsapptr{owner: owner} }

func unpackNSAPPTR(u *wirebb.Unpacker) (NSAPPTR, error) {
	n, err := u.Name()
	if err != nil {
		return nil, err
	}
	return nsapptr{owner: n}, nil
}
