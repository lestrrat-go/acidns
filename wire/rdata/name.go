package rdata

import (
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// CNAME is the canonical name rdata (RFC 1035 §3.3.1).
type CNAME interface {
	RData
	Target() wirebb.Name
}

type cname struct{ target wirebb.Name }

func (cname) Type() rrtype.Type       { return rrtype.CNAME }
func (c cname) Target() wirebb.Name   { return c.target }
func (c cname) Pack(p *wirebb.Packer) { p.Name(c.target) }

// NewCNAME returns a CNAME rdata.
func NewCNAME(target wirebb.Name) CNAME { return cname{target: target} }

func unpackCNAME(u *wirebb.Unpacker) (CNAME, error) {
	n, err := u.Name()
	if err != nil {
		return nil, err
	}
	return cname{target: n}, nil
}

// NS is the authoritative name server rdata (RFC 1035 §3.3.11).
type NS interface {
	RData
	NSDName() wirebb.Name
}

type ns struct{ name wirebb.Name }

func (ns) Type() rrtype.Type       { return rrtype.NS }
func (n ns) NSDName() wirebb.Name  { return n.name }
func (n ns) Pack(p *wirebb.Packer) { p.Name(n.name) }

// NewNS returns an NS rdata.
func NewNS(name wirebb.Name) NS { return ns{name: name} }

func unpackNS(u *wirebb.Unpacker) (NS, error) {
	n, err := u.Name()
	if err != nil {
		return nil, err
	}
	return ns{name: n}, nil
}

// PTR is the domain name pointer rdata (RFC 1035 §3.3.12).
type PTR interface {
	RData
	PtrDName() wirebb.Name
}

type ptr struct{ name wirebb.Name }

func (ptr) Type() rrtype.Type        { return rrtype.PTR }
func (p ptr) PtrDName() wirebb.Name  { return p.name }
func (p ptr) Pack(pk *wirebb.Packer) { pk.Name(p.name) }

// NewPTR returns a PTR rdata.
func NewPTR(name wirebb.Name) PTR { return ptr{name: name} }

func unpackPTR(u *wirebb.Unpacker) (PTR, error) {
	n, err := u.Name()
	if err != nil {
		return nil, err
	}
	return ptr{name: n}, nil
}
