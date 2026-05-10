package rdata

import (
	"fmt"

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

// NewMX returns an MX rdata. Returns [ErrInvalidRData] when exchange
// is the zero name; callers building a record from parsed configuration
// should propagate the error rather than silently emitting a record
// pointing at the root.
func NewMX(pref uint16, exchange wirebb.Name) (MX, error) {
	if !exchange.IsValid() {
		return MX{}, fmt.Errorf("%w: MX exchange name is invalid", ErrInvalidRData)
	}
	return MX{pref: pref, exchange: exchange}, nil
}

// MustNewMX is the panic-on-error variant of [NewMX].
func MustNewMX(pref uint16, exchange wirebb.Name) MX {
	m, err := NewMX(pref, exchange)
	if err != nil {
		panic(err)
	}
	return m
}

func unpackMX(u *wirebb.Unpacker, rdlen int) (MX, error) {
	var zero MX
	// preference(2) + minimum 1-byte name (root). Reject obvious garbage
	// up front so callers don't reach into a too-small rdata window.
	if rdlen < 3 {
		return zero, fmt.Errorf("%w: MX rdlen=%d, want >=3", ErrInvalidRData, rdlen)
	}
	end := u.Off() + rdlen
	pref, err := u.Uint16()
	if err != nil {
		return zero, err
	}
	n, err := u.NameInRange(end)
	if err != nil {
		return zero, err
	}
	return MX{pref: pref, exchange: n}, nil
}
