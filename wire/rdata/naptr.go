package rdata

import (
	"fmt"

	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// NAPTR is the naming-authority pointer rdata (RFC 3403).
type NAPTR struct {
	order, pref uint16
	flags       string
	services    string
	regexp      string
	replacement wirebb.Name
}

func (NAPTR) Type() rrtype.Type          { return rrtype.NAPTR }
func (NAPTR) typedRData()                {}
func (n NAPTR) Order() uint16            { return n.order }
func (n NAPTR) Preference() uint16       { return n.pref }
func (n NAPTR) Flags() string            { return n.flags }
func (n NAPTR) Services() string         { return n.services }
func (n NAPTR) Regexp() string           { return n.regexp }
func (n NAPTR) Replacement() wirebb.Name { return n.replacement }
func (n NAPTR) Pack(p *wirebb.Packer) {
	p.Uint16(n.order)
	p.Uint16(n.pref)
	_ = p.CharString([]byte(n.flags))
	_ = p.CharString([]byte(n.services))
	_ = p.CharString([]byte(n.regexp))
	p.NameUncompressed(n.replacement)
}

// NewNAPTR returns a NAPTR rdata. Each character string must be ≤ 255 bytes.
func NewNAPTR(order, pref uint16, flags, services, regexp string, replacement wirebb.Name) (NAPTR, error) {
	var zero NAPTR
	for label, s := range map[string]string{"flags": flags, "services": services, "regexp": regexp} {
		if len(s) > 255 {
			return zero, fmt.Errorf("%w: NAPTR %s exceeds 255 bytes", ErrInvalidRData, label)
		}
	}
	return NAPTR{
		order: order, pref: pref,
		flags: flags, services: services, regexp: regexp,
		replacement: replacement,
	}, nil
}

func unpackNAPTR(u *wirebb.Unpacker) (NAPTR, error) {
	var zero NAPTR
	order, err := u.Uint16()
	if err != nil {
		return zero, err
	}
	pref, err := u.Uint16()
	if err != nil {
		return zero, err
	}
	flags, err := u.CharString()
	if err != nil {
		return zero, err
	}
	services, err := u.CharString()
	if err != nil {
		return zero, err
	}
	regexp, err := u.CharString()
	if err != nil {
		return zero, err
	}
	replacement, err := u.Name()
	if err != nil {
		return zero, err
	}
	return NAPTR{
		order: order, pref: pref,
		flags: string(flags), services: string(services), regexp: string(regexp),
		replacement: replacement,
	}, nil
}
