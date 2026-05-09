package rdata

import (
	"slices"

	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// DHCID is the DHCP identifier rdata (RFC 4701). The wire format is opaque
// to the DNS layer; structure is defined in RFC 4701 §3.
type DHCID struct{ data []byte }

func (DHCID) Type() rrtype.Type       { return rrtype.DHCID }
func (DHCID) typedRData()             {}
func (d DHCID) Bytes() []byte         { return slices.Clone(d.data) }
func (d DHCID) Pack(p *wirebb.Packer) { p.Raw(d.data) }

// NewDHCID returns a DHCID rdata. The data bytes are copied.
func NewDHCID(data []byte) DHCID {
	cp := make([]byte, len(data))
	copy(cp, data)
	return DHCID{data: cp}
}

func unpackDHCID(u *wirebb.Unpacker, rdlen int) (DHCID, error) {
	var zero DHCID
	b, err := u.Bytes(rdlen)
	if err != nil {
		return zero, err
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	return DHCID{data: cp}, nil
}
