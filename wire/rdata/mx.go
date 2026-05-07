package rdata

import (
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// MX is the mail exchange rdata (RFC 1035 §3.3.9).
type MX interface {
	RData
	Preference() uint16
	Exchange() wirebb.Name
}

type mx struct {
	pref     uint16
	exchange wirebb.Name
}

func (mx) Type() rrtype.Type       { return rrtype.MX }
func (m mx) Preference() uint16    { return m.pref }
func (m mx) Exchange() wirebb.Name { return m.exchange }
func (m mx) Pack(p *wirebb.Packer) {
	p.Uint16(m.pref)
	p.Name(m.exchange)
}

// NewMX returns an MX rdata.
func NewMX(pref uint16, exchange wirebb.Name) MX {
	return mx{pref: pref, exchange: exchange}
}

func unpackMX(u *wirebb.Unpacker) (MX, error) {
	pref, err := u.Uint16()
	if err != nil {
		return nil, err
	}
	n, err := u.Name()
	if err != nil {
		return nil, err
	}
	return mx{pref: pref, exchange: n}, nil
}
