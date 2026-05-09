package rdata

import (
	"fmt"
	"net/netip"

	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// A is the IPv4 address rdata payload (RFC 1035 §3.4.1).
type A struct{ addr netip.Addr }

func (A) Type() rrtype.Type  { return rrtype.A }
func (A) typedRData()        {}
func (a A) Addr() netip.Addr { return a.addr }
func (a A) Pack(p *wirebb.Packer) {
	b := a.addr.As4()
	p.Raw(b[:])
}

// NewA returns an A rdata. It returns [ErrInvalidRData] when addr is
// not an IPv4 address.
func NewA(addr netip.Addr) (A, error) {
	if !addr.Is4() {
		return A{}, fmt.Errorf("%w: A requires IPv4 address, got %s", ErrInvalidRData, addr)
	}
	return A{addr: addr}, nil
}

// MustNewA is the panicking variant of [NewA] for tests and constants
// where a static IPv4 literal is known good. Production code that
// constructs A rdata from caller-supplied input should prefer NewA.
func MustNewA(addr netip.Addr) A {
	a, err := NewA(addr)
	if err != nil {
		panic(err)
	}
	return a
}

func unpackA(u *wirebb.Unpacker, rdlen int) (A, error) {
	var zero A
	if rdlen != 4 {
		return zero, fmt.Errorf("%w: A rdlen=%d, want 4", ErrInvalidRData, rdlen)
	}
	b, err := u.Bytes(4)
	if err != nil {
		return zero, err
	}
	return A{addr: netip.AddrFrom4([4]byte(b))}, nil
}

// AAAA is the IPv6 address rdata payload (RFC 3596).
type AAAA struct{ addr netip.Addr }

func (AAAA) Type() rrtype.Type  { return rrtype.AAAA }
func (AAAA) typedRData()        {}
func (a AAAA) Addr() netip.Addr { return a.addr }
func (a AAAA) Pack(p *wirebb.Packer) {
	b := a.addr.As16()
	p.Raw(b[:])
}

// NewAAAA returns an AAAA rdata. It returns [ErrInvalidRData] when
// addr is not an IPv6 address (an IPv4-mapped IPv6 address is accepted).
func NewAAAA(addr netip.Addr) (AAAA, error) {
	if !addr.Is6() {
		return AAAA{}, fmt.Errorf("%w: AAAA requires IPv6 address, got %s", ErrInvalidRData, addr)
	}
	return AAAA{addr: addr}, nil
}

// MustNewAAAA is the panicking variant of [NewAAAA] for tests and
// constants where a static IPv6 literal is known good.
func MustNewAAAA(addr netip.Addr) AAAA {
	a, err := NewAAAA(addr)
	if err != nil {
		panic(err)
	}
	return a
}

func unpackAAAA(u *wirebb.Unpacker, rdlen int) (AAAA, error) {
	var zero AAAA
	if rdlen != 16 {
		return zero, fmt.Errorf("%w: AAAA rdlen=%d, want 16", ErrInvalidRData, rdlen)
	}
	b, err := u.Bytes(16)
	if err != nil {
		return zero, err
	}
	return AAAA{addr: netip.AddrFrom16([16]byte(b))}, nil
}
