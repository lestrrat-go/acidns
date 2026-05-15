package rdata

import (
	"fmt"

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

// NewKX returns a KX rdata. The exchanger must be a valid name.
func NewKX(pref uint16, exchanger wirebb.Name) (KX, error) {
	if !exchanger.IsValid() {
		return KX{}, fmt.Errorf("%w: KX exchanger name is invalid", ErrInvalidRData)
	}
	return KX{pref: pref, exchange: exchanger}, nil
}
func unpackKX(u *wirebb.Unpacker, rdlen int) (KX, error) {
	var zero KX
	end := u.Off() + rdlen
	pref, err := u.Uint16()
	if err != nil {
		return zero, err
	}
	n, err := u.UncompressedName(end - u.Off())
	if err != nil {
		return zero, err
	}
	return KX{pref: pref, exchange: n}, nil
}
