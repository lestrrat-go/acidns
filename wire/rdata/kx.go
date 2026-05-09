package rdata

import (
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// KX is the Key Exchanger rdata (RFC 2230 §3.1). Wire shape mirrors MX.
// Per RFC 3597 §4 the exchanger name MUST NOT be compressed on the wire.
type KX struct {
	pref     uint16
	exchange wirebb.Name
}

func (KX) Type() rrtype.Type        { return rrtype.KX }
func (KX) typedRData()              {}
func (k KX) Preference() uint16     { return k.pref }
func (k KX) Exchanger() wirebb.Name { return k.exchange }
func (k KX) Pack(p *wirebb.Packer) {
	p.Uint16(k.pref)
	p.NameUncompressed(k.exchange)
}

// NewKX returns a KX rdata.
func NewKX(pref uint16, exchanger wirebb.Name) KX {
	return KX{pref: pref, exchange: exchanger}
}

func unpackKX(u *wirebb.Unpacker, rdlen int) (KX, error) {
	var zero KX
	end := u.Off() + rdlen
	pref, err := u.Uint16()
	if err != nil {
		return zero, err
	}
	n, err := u.UncompressedNameInRange(end)
	if err != nil {
		return zero, err
	}
	return KX{pref: pref, exchange: n}, nil
}
