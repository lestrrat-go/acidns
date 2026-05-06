package rdata

import (
	"fmt"
	"net/netip"

	"github.com/lestrrat-go/acidns/dnsmsg/internal/wire"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
)

// APLAddressFamily identifies an AFI as registered with IANA. Only IPv4 (1)
// and IPv6 (2) are defined for use in APL records.
type APLAddressFamily uint16

const (
	APLFamilyIPv4 APLAddressFamily = 1
	APLFamilyIPv6 APLAddressFamily = 2
)

// APLItem is a single prefix entry inside an APL rdata payload (RFC 3123).
type APLItem interface {
	Family() APLAddressFamily
	Prefix() netip.Prefix
	Negate() bool
}

type aplItem struct {
	family APLAddressFamily
	prefix netip.Prefix
	neg    bool
}

func (a aplItem) Family() APLAddressFamily { return a.family }
func (a aplItem) Prefix() netip.Prefix     { return a.prefix }
func (a aplItem) Negate() bool             { return a.neg }

// NewAPLItem returns an APL item. The prefix's address family is inferred
// from the prefix; IPv4 maps to family 1, IPv6 to family 2.
func NewAPLItem(prefix netip.Prefix, negate bool) (APLItem, error) {
	if !prefix.IsValid() {
		return nil, fmt.Errorf("%w: APL prefix invalid", ErrInvalidRData)
	}
	family := APLFamilyIPv4
	if prefix.Addr().Is6() {
		family = APLFamilyIPv6
	}
	return aplItem{family: family, prefix: prefix, neg: negate}, nil
}

// APL is the Address Prefix List rdata (RFC 3123).
type APL interface {
	RData
	Items() []APLItem
}

type apl struct{ items []APLItem }

func (apl) Type() rrtype.Type   { return rrtype.APL }
func (a apl) Items() []APLItem  { return a.items }
func (a apl) Pack(p *wire.Packer) {
	for _, it := range a.items {
		p.Uint16(uint16(it.Family()))
		p.Uint8(uint8(it.Prefix().Bits()))
		afd := encodeAPLAFD(it.Prefix())
		nlen := uint8(len(afd)) & 0x7f
		if it.Negate() {
			nlen |= 0x80
		}
		p.Uint8(nlen)
		p.Raw(afd)
	}
}

// NewAPL returns an APL rdata containing the supplied items in order.
func NewAPL(items ...APLItem) APL {
	cp := make([]APLItem, len(items))
	copy(cp, items)
	return apl{items: cp}
}

func unpackAPL(u *wire.Unpacker, rdlen int) (APL, error) {
	end := u.Off() + rdlen
	var items []APLItem
	for u.Off() < end {
		fam, err := u.Uint16()
		if err != nil {
			return nil, err
		}
		prefix, err := u.Uint8()
		if err != nil {
			return nil, err
		}
		nlen, err := u.Uint8()
		if err != nil {
			return nil, err
		}
		alen := int(nlen & 0x7f)
		neg := nlen&0x80 != 0
		afd, err := u.Bytes(alen)
		if err != nil {
			return nil, err
		}
		p, err := decodeAPLAFD(APLAddressFamily(fam), prefix, afd)
		if err != nil {
			return nil, err
		}
		items = append(items, aplItem{family: APLAddressFamily(fam), prefix: p, neg: neg})
	}
	return apl{items: items}, nil
}

func encodeAPLAFD(p netip.Prefix) []byte {
	var raw []byte
	if p.Addr().Is4() {
		b := p.Addr().As4()
		raw = b[:]
	} else {
		b := p.Addr().As16()
		raw = b[:]
	}
	// Strip trailing zero bytes per RFC 3123 §4.1.
	for len(raw) > 0 && raw[len(raw)-1] == 0 {
		raw = raw[:len(raw)-1]
	}
	return raw
}

func decodeAPLAFD(family APLAddressFamily, prefix uint8, afd []byte) (netip.Prefix, error) {
	switch family {
	case APLFamilyIPv4:
		if prefix > 32 || len(afd) > 4 {
			return netip.Prefix{}, fmt.Errorf("%w: APL IPv4 prefix=%d afdlen=%d", ErrInvalidRData, prefix, len(afd))
		}
		var b [4]byte
		copy(b[:], afd)
		return netip.PrefixFrom(netip.AddrFrom4(b), int(prefix)), nil
	case APLFamilyIPv6:
		if prefix > 128 || len(afd) > 16 {
			return netip.Prefix{}, fmt.Errorf("%w: APL IPv6 prefix=%d afdlen=%d", ErrInvalidRData, prefix, len(afd))
		}
		var b [16]byte
		copy(b[:], afd)
		return netip.PrefixFrom(netip.AddrFrom16(b), int(prefix)), nil
	default:
		return netip.Prefix{}, fmt.Errorf("%w: APL unknown family %d", ErrInvalidRData, family)
	}
}
