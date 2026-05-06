package rdata

import (
	"github.com/lestrrat-go/acidns/dnsmsg/internal/wire"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
)

// CNAME is the canonical name rdata (RFC 1035 §3.3.1).
type CNAME interface {
	RData
	Target() dnsname.Name
}

type cname struct{ target dnsname.Name }

func (cname) Type() rrtype.Type      { return rrtype.CNAME }
func (c cname) Target() dnsname.Name { return c.target }
func (c cname) Pack(p *wire.Packer)  { p.Name(c.target) }

// NewCNAME returns a CNAME rdata.
func NewCNAME(target dnsname.Name) CNAME { return cname{target: target} }

func unpackCNAME(u *wire.Unpacker) (CNAME, error) {
	n, err := u.Name()
	if err != nil {
		return nil, err
	}
	return cname{target: n}, nil
}

// NS is the authoritative name server rdata (RFC 1035 §3.3.11).
type NS interface {
	RData
	NSDName() dnsname.Name
}

type ns struct{ name dnsname.Name }

func (ns) Type() rrtype.Type       { return rrtype.NS }
func (n ns) NSDName() dnsname.Name { return n.name }
func (n ns) Pack(p *wire.Packer)   { p.Name(n.name) }

// NewNS returns an NS rdata.
func NewNS(name dnsname.Name) NS { return ns{name: name} }

func unpackNS(u *wire.Unpacker) (NS, error) {
	n, err := u.Name()
	if err != nil {
		return nil, err
	}
	return ns{name: n}, nil
}

// PTR is the domain name pointer rdata (RFC 1035 §3.3.12).
type PTR interface {
	RData
	PtrDName() dnsname.Name
}

type ptr struct{ name dnsname.Name }

func (ptr) Type() rrtype.Type        { return rrtype.PTR }
func (p ptr) PtrDName() dnsname.Name { return p.name }
func (p ptr) Pack(pk *wire.Packer)   { pk.Name(p.name) }

// NewPTR returns a PTR rdata.
func NewPTR(name dnsname.Name) PTR { return ptr{name: name} }

func unpackPTR(u *wire.Unpacker) (PTR, error) {
	n, err := u.Name()
	if err != nil {
		return nil, err
	}
	return ptr{name: n}, nil
}
