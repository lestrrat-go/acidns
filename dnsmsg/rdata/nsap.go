package rdata

import (
	"github.com/lestrrat-go/acidns/dnsmsg/internal/wire"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
)

// NSAP is the Network Service Access Point address rdata (RFC 1706, formerly
// RFC 1348). The wire format is the raw NSAP address bytes, no length prefix.
type NSAP interface {
	RData
	Address() []byte
}

type nsap struct{ addr []byte }

func (nsap) Type() rrtype.Type    { return rrtype.NSAP }
func (n nsap) Address() []byte    { return n.addr }
func (n nsap) Pack(p *wire.Packer) { p.Raw(n.addr) }

// NewNSAP returns an NSAP rdata. The address bytes are copied.
func NewNSAP(addr []byte) NSAP {
	cp := make([]byte, len(addr))
	copy(cp, addr)
	return nsap{addr: cp}
}

func unpackNSAP(u *wire.Unpacker, rdlen int) (NSAP, error) {
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
	Owner() dnsname.Name
}

type nsapptr struct{ owner dnsname.Name }

func (nsapptr) Type() rrtype.Type     { return rrtype.NSAPPTR }
func (n nsapptr) Owner() dnsname.Name { return n.owner }
func (n nsapptr) Pack(p *wire.Packer) { p.Name(n.owner) }

// NewNSAPPTR returns an NSAP-PTR rdata.
func NewNSAPPTR(owner dnsname.Name) NSAPPTR { return nsapptr{owner: owner} }

func unpackNSAPPTR(u *wire.Unpacker) (NSAPPTR, error) {
	n, err := u.Name()
	if err != nil {
		return nil, err
	}
	return nsapptr{owner: n}, nil
}
