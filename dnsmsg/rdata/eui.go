package rdata

import (
	"fmt"

	"github.com/lestrrat-go/acidns/dnsmsg/internal/wire"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
)

// EUI48 is the 48-bit MAC address rdata (RFC 7043 §3).
type EUI48 interface {
	RData
	Address() [6]byte
}

type eui48 struct{ addr [6]byte }

func (eui48) Type() rrtype.Type     { return rrtype.EUI48 }
func (e eui48) Address() [6]byte    { return e.addr }
func (e eui48) Pack(p *wire.Packer) { p.Raw(e.addr[:]) }

// NewEUI48 returns an EUI48 rdata.
func NewEUI48(addr [6]byte) EUI48 { return eui48{addr: addr} }

func unpackEUI48(u *wire.Unpacker, rdlen int) (EUI48, error) {
	if rdlen != 6 {
		return nil, fmt.Errorf("%w: EUI48 rdlen=%d, want 6", ErrInvalidRData, rdlen)
	}
	b, err := u.Bytes(6)
	if err != nil {
		return nil, err
	}
	return eui48{addr: [6]byte(b)}, nil
}

// EUI64 is the 64-bit MAC address rdata (RFC 7043 §4).
type EUI64 interface {
	RData
	Address() [8]byte
}

type eui64 struct{ addr [8]byte }

func (eui64) Type() rrtype.Type     { return rrtype.EUI64 }
func (e eui64) Address() [8]byte    { return e.addr }
func (e eui64) Pack(p *wire.Packer) { p.Raw(e.addr[:]) }

// NewEUI64 returns an EUI64 rdata.
func NewEUI64(addr [8]byte) EUI64 { return eui64{addr: addr} }

func unpackEUI64(u *wire.Unpacker, rdlen int) (EUI64, error) {
	if rdlen != 8 {
		return nil, fmt.Errorf("%w: EUI64 rdlen=%d, want 8", ErrInvalidRData, rdlen)
	}
	b, err := u.Bytes(8)
	if err != nil {
		return nil, err
	}
	return eui64{addr: [8]byte(b)}, nil
}
