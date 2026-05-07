package rdata

import (
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// MX is the mail exchange rdata (RFC 1035 §3.3.9).
type MX struct {
	pref     uint16
	exchange wirebb.Name
}

func (MX) Type() rrtype.Type       { return rrtype.MX }
func (MX) typedRData()             {}
func (m MX) Preference() uint16    { return m.pref }
func (m MX) Exchange() wirebb.Name { return m.exchange }
func (m MX) Pack(p *wirebb.Packer) {
	p.Uint16(m.pref)
	p.Name(m.exchange)
}

// NewMX returns an MX rdata.
func NewMX(pref uint16, exchange wirebb.Name) MX {
	return MX{pref: pref, exchange: exchange}
}

func unpackMX(u *wirebb.Unpacker) (MX, error) {
	var zero MX
	pref, err := u.Uint16()
	if err != nil {
		return zero, err
	}
	n, err := u.Name()
	if err != nil {
		return zero, err
	}
	return MX{pref: pref, exchange: n}, nil
}
