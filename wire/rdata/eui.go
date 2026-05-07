package rdata

import (
	"fmt"

	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// EUI48 is the 48-bit MAC address rdata (RFC 7043 §3).
type EUI48 struct{ addr [6]byte }

func (EUI48) Type() rrtype.Type       { return rrtype.EUI48 }
func (EUI48) typedRData()             {}
func (e EUI48) Address() [6]byte      { return e.addr }
func (e EUI48) Pack(p *wirebb.Packer) { p.Raw(e.addr[:]) }

// NewEUI48 returns an EUI48 rdata.
func NewEUI48(addr [6]byte) EUI48 { return EUI48{addr: addr} }

func unpackEUI48(u *wirebb.Unpacker, rdlen int) (EUI48, error) {
	var zero EUI48
	if rdlen != 6 {
		return zero, fmt.Errorf("%w: EUI48 rdlen=%d, want 6", ErrInvalidRData, rdlen)
	}
	b, err := u.Bytes(6)
	if err != nil {
		return zero, err
	}
	return EUI48{addr: [6]byte(b)}, nil
}

// EUI64 is the 64-bit MAC address rdata (RFC 7043 §4).
type EUI64 struct{ addr [8]byte }

func (EUI64) Type() rrtype.Type       { return rrtype.EUI64 }
func (EUI64) typedRData()             {}
func (e EUI64) Address() [8]byte      { return e.addr }
func (e EUI64) Pack(p *wirebb.Packer) { p.Raw(e.addr[:]) }

// NewEUI64 returns an EUI64 rdata.
func NewEUI64(addr [8]byte) EUI64 { return EUI64{addr: addr} }

func unpackEUI64(u *wirebb.Unpacker, rdlen int) (EUI64, error) {
	var zero EUI64
	if rdlen != 8 {
		return zero, fmt.Errorf("%w: EUI64 rdlen=%d, want 8", ErrInvalidRData, rdlen)
	}
	b, err := u.Bytes(8)
	if err != nil {
		return zero, err
	}
	return EUI64{addr: [8]byte(b)}, nil
}
