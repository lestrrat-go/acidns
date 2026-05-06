package rdata

import (
	"fmt"

	"github.com/lestrrat-go/acidns/dnsmsg/internal/wire"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
)

// NAPTR is the naming-authority pointer rdata (RFC 3403).
type NAPTR interface {
	RData
	Order() uint16
	Preference() uint16
	Flags() string
	Services() string
	Regexp() string
	Replacement() dnsname.Name
}

type naptr struct {
	order, pref uint16
	flags       string
	services    string
	regexp      string
	replacement dnsname.Name
}

func (naptr) Type() rrtype.Type           { return rrtype.NAPTR }
func (n naptr) Order() uint16             { return n.order }
func (n naptr) Preference() uint16        { return n.pref }
func (n naptr) Flags() string             { return n.flags }
func (n naptr) Services() string          { return n.services }
func (n naptr) Regexp() string            { return n.regexp }
func (n naptr) Replacement() dnsname.Name { return n.replacement }
func (n naptr) Pack(p *wire.Packer) {
	p.Uint16(n.order)
	p.Uint16(n.pref)
	_ = p.CharString([]byte(n.flags))
	_ = p.CharString([]byte(n.services))
	_ = p.CharString([]byte(n.regexp))
	p.NameUncompressed(n.replacement)
}

// NewNAPTR returns a NAPTR rdata. Each character string must be ≤ 255 bytes.
func NewNAPTR(order, pref uint16, flags, services, regexp string, replacement dnsname.Name) (NAPTR, error) {
	for label, s := range map[string]string{"flags": flags, "services": services, "regexp": regexp} {
		if len(s) > 255 {
			return nil, fmt.Errorf("%w: NAPTR %s exceeds 255 bytes", ErrInvalidRData, label)
		}
	}
	return naptr{
		order: order, pref: pref,
		flags: flags, services: services, regexp: regexp,
		replacement: replacement,
	}, nil
}

func unpackNAPTR(u *wire.Unpacker) (NAPTR, error) {
	order, err := u.Uint16()
	if err != nil {
		return nil, err
	}
	pref, err := u.Uint16()
	if err != nil {
		return nil, err
	}
	flags, err := u.CharString()
	if err != nil {
		return nil, err
	}
	services, err := u.CharString()
	if err != nil {
		return nil, err
	}
	regexp, err := u.CharString()
	if err != nil {
		return nil, err
	}
	replacement, err := u.Name()
	if err != nil {
		return nil, err
	}
	return naptr{
		order: order, pref: pref,
		flags: string(flags), services: string(services), regexp: string(regexp),
		replacement: replacement,
	}, nil
}
