package rdata

import (
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// CNAME is the canonical name rdata (RFC 1035 §3.3.1).
type CNAME struct{ target wirebb.Name }

func (CNAME) Type() rrtype.Type       { return rrtype.CNAME }
func (CNAME) typedRData()             {}
func (c CNAME) Target() wirebb.Name   { return c.target }
func (c CNAME) Pack(p *wirebb.Packer) { p.Name(c.target) }

// NewCNAME returns a CNAME rdata.
func NewCNAME(target wirebb.Name) CNAME { return CNAME{target: target} }

func unpackCNAME(u *wirebb.Unpacker) (CNAME, error) {
	var zero CNAME
	n, err := u.Name()
	if err != nil {
		return zero, err
	}
	return CNAME{target: n}, nil
}

// NS is the authoritative name server rdata (RFC 1035 §3.3.11).
type NS struct{ name wirebb.Name }

func (NS) Type() rrtype.Type       { return rrtype.NS }
func (NS) typedRData()             {}
func (n NS) NSDName() wirebb.Name  { return n.name }
func (n NS) Pack(p *wirebb.Packer) { p.Name(n.name) }

// NewNS returns an NS rdata.
func NewNS(name wirebb.Name) NS { return NS{name: name} }

func unpackNS(u *wirebb.Unpacker) (NS, error) {
	var zero NS
	n, err := u.Name()
	if err != nil {
		return zero, err
	}
	return NS{name: n}, nil
}

// PTR is the domain name pointer rdata (RFC 1035 §3.3.12).
type PTR struct{ name wirebb.Name }

func (PTR) Type() rrtype.Type        { return rrtype.PTR }
func (PTR) typedRData()              {}
func (p PTR) PtrDName() wirebb.Name  { return p.name }
func (p PTR) Pack(pk *wirebb.Packer) { pk.Name(p.name) }

// NewPTR returns a PTR rdata.
func NewPTR(name wirebb.Name) PTR { return PTR{name: name} }

func unpackPTR(u *wirebb.Unpacker) (PTR, error) {
	var zero PTR
	n, err := u.Name()
	if err != nil {
		return zero, err
	}
	return PTR{name: n}, nil
}
