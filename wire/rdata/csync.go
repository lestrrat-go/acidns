package rdata

import (
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// CSYNC is the child-to-parent synchronisation rdata (RFC 7477) used to
// instruct a parent zone to synchronise NS / A / AAAA records from the
// child.
type CSYNC interface {
	RData
	SOASerial() uint32
	Flags() uint16
	Types() []rrtype.Type
}

type csync struct {
	soaSerial uint32
	flags     uint16
	types     []rrtype.Type
}

func (csync) Type() rrtype.Type      { return rrtype.CSYNC }
func (c csync) SOASerial() uint32    { return c.soaSerial }
func (c csync) Flags() uint16        { return c.flags }
func (c csync) Types() []rrtype.Type { return c.types }
func (c csync) Pack(p *wirebb.Packer) {
	p.Uint32(c.soaSerial)
	p.Uint16(c.flags)
	encodeTypeBitmap(p, c.types)
}

// NewCSYNC returns a CSYNC rdata.
func NewCSYNC(soaSerial uint32, flags uint16, types []rrtype.Type) CSYNC {
	cp := append([]rrtype.Type(nil), types...)
	return csync{soaSerial: soaSerial, flags: flags, types: cp}
}

func unpackCSYNC(u *wirebb.Unpacker, rdlen int) (CSYNC, error) {
	end := u.Off() + rdlen
	serial, err := u.Uint32()
	if err != nil {
		return nil, err
	}
	flags, err := u.Uint16()
	if err != nil {
		return nil, err
	}
	types, err := decodeTypeBitmap(u, end-u.Off())
	if err != nil {
		return nil, err
	}
	return csync{soaSerial: serial, flags: flags, types: types}, nil
}
