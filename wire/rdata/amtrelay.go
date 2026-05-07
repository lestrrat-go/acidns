package rdata

import (
	"fmt"
	"net/netip"

	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// AMTRELAYType identifies the relay encoding used in an AMTRELAY rdata
// (RFC 8777 §4.2.2). Values share the IANA "AMTRELAY" registry with the
// underlying 7-bit field.
type AMTRELAYType uint8

const (
	AMTRELAYTypeNone AMTRELAYType = 0
	AMTRELAYTypeIPv4 AMTRELAYType = 1
	AMTRELAYTypeIPv6 AMTRELAYType = 2
	AMTRELAYTypeName AMTRELAYType = 3
)

// AMTRELAY is the Automatic Multicast Tunnelling relay rdata (RFC 8777
// §4). The D bit signals that the relay is the default discovery relay
// (RFC 8777 §4.2.1); RelayAddr is set when RelayType is IPv4 or IPv6,
// RelayName when it is Name, and both are zero when it is None.
type AMTRELAY struct {
	prec      uint8
	discovery bool
	rt        AMTRELAYType
	relayAddr netip.Addr
	relayName wirebb.Name
}

func (AMTRELAY) Type() rrtype.Type        { return rrtype.AMTRELAY }
func (AMTRELAY) typedRData()              {}
func (a AMTRELAY) Precedence() uint8      { return a.prec }
func (a AMTRELAY) Discovery() bool        { return a.discovery }
func (a AMTRELAY) RelayType() AMTRELAYType { return a.rt }
func (a AMTRELAY) RelayAddr() netip.Addr  { return a.relayAddr }
func (a AMTRELAY) RelayName() wirebb.Name { return a.relayName }
func (a AMTRELAY) Pack(p *wirebb.Packer) {
	p.Uint8(a.prec)
	b := uint8(a.rt) & 0x7f
	if a.discovery {
		b |= 0x80
	}
	p.Uint8(b)
	switch a.rt {
	case AMTRELAYTypeIPv4:
		v := a.relayAddr.As4()
		p.Raw(v[:])
	case AMTRELAYTypeIPv6:
		v := a.relayAddr.As16()
		p.Raw(v[:])
	case AMTRELAYTypeName:
		// RFC 8777 §4.3.3: relay name MUST NOT be compressed.
		p.NameUncompressed(a.relayName)
	}
}

// NewAMTRELAYNone returns an AMTRELAY rdata with no relay (type 0).
func NewAMTRELAYNone(prec uint8, discovery bool) AMTRELAY {
	return AMTRELAY{prec: prec, discovery: discovery, rt: AMTRELAYTypeNone}
}

// NewAMTRELAYAddr returns an AMTRELAY rdata whose relay is an IPv4 or
// IPv6 address.
func NewAMTRELAYAddr(prec uint8, discovery bool, addr netip.Addr) (AMTRELAY, error) {
	var zero AMTRELAY
	rt := AMTRELAYTypeIPv4
	switch {
	case addr.Is4():
		rt = AMTRELAYTypeIPv4
	case addr.Is6():
		rt = AMTRELAYTypeIPv6
	default:
		return zero, fmt.Errorf("%w: AMTRELAY address must be IPv4 or IPv6", ErrInvalidRData)
	}
	return AMTRELAY{prec: prec, discovery: discovery, rt: rt, relayAddr: addr}, nil
}

// NewAMTRELAYName returns an AMTRELAY rdata whose relay is a domain name.
func NewAMTRELAYName(prec uint8, discovery bool, name wirebb.Name) AMTRELAY {
	return AMTRELAY{prec: prec, discovery: discovery, rt: AMTRELAYTypeName, relayName: name}
}

func unpackAMTRELAY(u *wirebb.Unpacker, rdlen int) (AMTRELAY, error) {
	var zero AMTRELAY
	if rdlen < 2 {
		return zero, fmt.Errorf("%w: AMTRELAY rdlen %d < 2", ErrInvalidRData, rdlen)
	}
	end := u.Off() + rdlen
	prec, err := u.Uint8()
	if err != nil {
		return zero, err
	}
	b, err := u.Uint8()
	if err != nil {
		return zero, err
	}
	a := AMTRELAY{
		prec:      prec,
		discovery: b&0x80 != 0,
		rt:        AMTRELAYType(b & 0x7f),
	}
	switch a.rt {
	case AMTRELAYTypeNone:
		// no relay
	case AMTRELAYTypeIPv4:
		raw, err := u.Bytes(4)
		if err != nil {
			return zero, err
		}
		a.relayAddr = netip.AddrFrom4([4]byte(raw))
	case AMTRELAYTypeIPv6:
		raw, err := u.Bytes(16)
		if err != nil {
			return zero, err
		}
		a.relayAddr = netip.AddrFrom16([16]byte(raw))
	case AMTRELAYTypeName:
		n, err := u.Name()
		if err != nil {
			return zero, err
		}
		a.relayName = n
	default:
		return zero, fmt.Errorf("%w: AMTRELAY unknown relay type %d", ErrInvalidRData, a.rt)
	}
	if u.Off() != end {
		return zero, fmt.Errorf("%w: AMTRELAY trailing %d bytes", ErrInvalidRData, end-u.Off())
	}
	return a, nil
}
