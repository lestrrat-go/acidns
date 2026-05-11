package rdata

import (
	"fmt"

	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// NSAP is the Network Service Access Point address rdata (RFC 1706, formerly
// RFC 1348). The wire format is the raw NSAP address bytes, no length prefix.
type NSAP struct{ addr []byte }

func (NSAP) Type() rrtype.Type       { return rrtype.NSAP }
func (NSAP) typedRData()             {}
func (n NSAP) Address() []byte       { return n.addr }
func (n NSAP) Pack(p *wirebb.Packer) { p.Raw(n.addr) }

// NewNSAP returns an NSAP rdata. The address bytes are copied.
func NewNSAP(addr []byte) NSAP {
	cp := make([]byte, len(addr))
	copy(cp, addr)
	return NSAP{addr: cp}
}

func unpackNSAP(u *wirebb.Unpacker, rdlen int) (NSAP, error) {
	var zero NSAP
	b, err := u.Bytes(rdlen)
	if err != nil {
		return zero, err
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	return NSAP{addr: cp}, nil
}

// NSAPPTR is the NSAP-PTR rdata (RFC 1706 §6).
type NSAPPTR struct{ owner wirebb.Name }

func (NSAPPTR) Type() rrtype.Type       { return rrtype.NSAPPTR }
func (NSAPPTR) typedRData()             {}
func (n NSAPPTR) Owner() wirebb.Name    { return n.owner }
func (n NSAPPTR) Pack(p *wirebb.Packer) { p.Name(n.owner) }

// NewNSAPPTR returns an NSAP-PTR rdata. The owner must be a valid name.
func NewNSAPPTR(owner wirebb.Name) (NSAPPTR, error) {
	if !owner.IsValid() {
		return NSAPPTR{}, fmt.Errorf("%w: NSAP-PTR owner name is invalid", ErrInvalidRData)
	}
	return NSAPPTR{owner: owner}, nil
}
func unpackNSAPPTR(u *wirebb.Unpacker, rdlen int) (NSAPPTR, error) {
	var zero NSAPPTR
	n, err := u.NameInRange(u.Off() + rdlen)
	if err != nil {
		return zero, err
	}
	return NSAPPTR{owner: n}, nil
}
