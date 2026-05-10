package rdata

import (
	"fmt"

	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// CNAME is the canonical name rdata (RFC 1035 §3.3.1).
type CNAME struct{ target wirebb.Name }

func (CNAME) Type() rrtype.Type       { return rrtype.CNAME }
func (CNAME) typedRData()             {}
func (c CNAME) Target() wirebb.Name   { return c.target }
func (c CNAME) Pack(p *wirebb.Packer) { p.Name(c.target) }

// NewCNAME returns a CNAME rdata. The target must be a valid name.
func NewCNAME(target wirebb.Name) (CNAME, error) {
	if !target.IsValid() {
		return CNAME{}, fmt.Errorf("%w: CNAME target name is invalid", ErrInvalidRData)
	}
	return CNAME{target: target}, nil
}

// MustNewCNAME is the panic-on-error variant of [NewCNAME].
func MustNewCNAME(target wirebb.Name) CNAME {
	c, err := NewCNAME(target)
	if err != nil {
		panic(err)
	}
	return c
}

func unpackCNAME(u *wirebb.Unpacker, rdlen int) (CNAME, error) {
	var zero CNAME
	n, err := u.NameInRange(u.Off() + rdlen)
	if err != nil {
		return zero, err
	}
	return CNAME{target: n}, nil
}

// NS is the authoritative name server rdata (RFC 1035 §3.3.11).
type NS struct{ name wirebb.Name }

func (NS) Type() rrtype.Type       { return rrtype.NS }
func (NS) typedRData()             {}
func (n NS) Target() wirebb.Name   { return n.name }
func (n NS) Pack(p *wirebb.Packer) { p.Name(n.name) }

// NewNS returns an NS rdata. The nsdname must be a valid name.
func NewNS(name wirebb.Name) (NS, error) {
	if !name.IsValid() {
		return NS{}, fmt.Errorf("%w: NS name is invalid", ErrInvalidRData)
	}
	return NS{name: name}, nil
}

// MustNewNS is the panic-on-error variant of [NewNS].
func MustNewNS(name wirebb.Name) NS {
	n, err := NewNS(name)
	if err != nil {
		panic(err)
	}
	return n
}

func unpackNS(u *wirebb.Unpacker, rdlen int) (NS, error) {
	var zero NS
	n, err := u.NameInRange(u.Off() + rdlen)
	if err != nil {
		return zero, err
	}
	return NS{name: n}, nil
}

// PTR is the domain name pointer rdata (RFC 1035 §3.3.12).
type PTR struct{ name wirebb.Name }

func (PTR) Type() rrtype.Type        { return rrtype.PTR }
func (PTR) typedRData()              {}
func (p PTR) Target() wirebb.Name    { return p.name }
func (p PTR) Pack(pk *wirebb.Packer) { pk.Name(p.name) }

// NewPTR returns a PTR rdata. The ptrdname must be a valid name.
func NewPTR(name wirebb.Name) (PTR, error) {
	if !name.IsValid() {
		return PTR{}, fmt.Errorf("%w: PTR name is invalid", ErrInvalidRData)
	}
	return PTR{name: name}, nil
}

// MustNewPTR is the panic-on-error variant of [NewPTR].
func MustNewPTR(name wirebb.Name) PTR {
	p, err := NewPTR(name)
	if err != nil {
		panic(err)
	}
	return p
}

func unpackPTR(u *wirebb.Unpacker, rdlen int) (PTR, error) {
	var zero PTR
	n, err := u.NameInRange(u.Off() + rdlen)
	if err != nil {
		return zero, err
	}
	return PTR{name: n}, nil
}
