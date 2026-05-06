package rdata

import (
	"fmt"
	"net/netip"

	"github.com/lestrrat-go/acidns/dnsmsg/internal/wire"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
)

// A is the IPv4 address rdata payload (RFC 1035 §3.4.1).
type A interface {
	RData
	Addr() netip.Addr
}

type aData struct{ addr netip.Addr }

func (aData) Type() rrtype.Type  { return rrtype.A }
func (a aData) Addr() netip.Addr { return a.addr }
func (a aData) Pack(p *wire.Packer) {
	b := a.addr.As4()
	p.Raw(b[:])
}

// NewA returns an A rdata. It panics if addr is not a 4-byte IPv4 address.
func NewA(addr netip.Addr) A {
	if !addr.Is4() {
		panic(fmt.Errorf("%w: A requires IPv4 address, got %s", ErrInvalidRData, addr))
	}
	return aData{addr: addr}
}

func unpackA(u *wire.Unpacker) (A, error) {
	b, err := u.Bytes(4)
	if err != nil {
		return nil, err
	}
	return aData{addr: netip.AddrFrom4([4]byte(b))}, nil
}

// AAAA is the IPv6 address rdata payload (RFC 3596).
type AAAA interface {
	RData
	Addr() netip.Addr
}

type aaaaData struct{ addr netip.Addr }

func (aaaaData) Type() rrtype.Type  { return rrtype.AAAA }
func (a aaaaData) Addr() netip.Addr { return a.addr }
func (a aaaaData) Pack(p *wire.Packer) {
	b := a.addr.As16()
	p.Raw(b[:])
}

// NewAAAA returns an AAAA rdata. It panics if addr is not a 16-byte IPv6
// address (an IPv4-mapped IPv6 address is accepted).
func NewAAAA(addr netip.Addr) AAAA {
	if !addr.Is6() {
		panic(fmt.Errorf("%w: AAAA requires IPv6 address, got %s", ErrInvalidRData, addr))
	}
	return aaaaData{addr: addr}
}

func unpackAAAA(u *wire.Unpacker) (AAAA, error) {
	b, err := u.Bytes(16)
	if err != nil {
		return nil, err
	}
	return aaaaData{addr: netip.AddrFrom16([16]byte(b))}, nil
}
