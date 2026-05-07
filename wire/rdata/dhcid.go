package rdata

import (
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// DHCID is the DHCP identifier rdata (RFC 4701). The wire format is opaque
// to the DNS layer; structure is defined in RFC 4701 §3.
type DHCID interface {
	RData
	Bytes() []byte
}

type dhcid struct{ data []byte }

func (dhcid) Type() rrtype.Type       { return rrtype.DHCID }
func (d dhcid) Bytes() []byte         { return d.data }
func (d dhcid) Pack(p *wirebb.Packer) { p.Raw(d.data) }

// NewDHCID returns a DHCID rdata. The data bytes are copied.
func NewDHCID(data []byte) DHCID {
	cp := make([]byte, len(data))
	copy(cp, data)
	return dhcid{data: cp}
}

func unpackDHCID(u *wirebb.Unpacker, rdlen int) (DHCID, error) {
	b, err := u.Bytes(rdlen)
	if err != nil {
		return nil, err
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	return dhcid{data: cp}, nil
}
