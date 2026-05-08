package rdata

import (
	"fmt"

	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// CAA is the certification authority authorisation rdata (RFC 8659).
type CAA struct {
	flags uint8
	tag   string
	value []byte
}

func (CAA) Type() rrtype.Type { return rrtype.CAA }
func (CAA) typedRData()       {}
func (c CAA) Flags() uint8    { return c.flags }
func (c CAA) Tag() string     { return c.tag }
func (c CAA) Value() []byte   { return c.value }
func (c CAA) Pack(p *wirebb.Packer) {
	p.Uint8(c.flags)
	p.Uint8(uint8(len(c.tag)))
	p.Raw([]byte(c.tag))
	p.Raw(c.value)
}

// NewCAA returns a CAA rdata. Tag must be 1–15 ASCII letters/digits per
// RFC 8659 §4.1.1.
func NewCAA(flags uint8, tag string, value []byte) (CAA, error) {
	var zero CAA
	if len(tag) == 0 || len(tag) > 15 {
		return zero, fmt.Errorf("%w: CAA tag must be 1-15 bytes", ErrInvalidRData)
	}
	for i := range len(tag) {
		c := tag[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !ok {
			return zero, fmt.Errorf("%w: CAA tag must be alnum", ErrInvalidRData)
		}
	}
	cp := make([]byte, len(value))
	copy(cp, value)
	return CAA{flags: flags, tag: tag, value: cp}, nil
}

func unpackCAA(u *wirebb.Unpacker, rdlen int) (CAA, error) {
	var zero CAA
	end := u.Off() + rdlen
	flags, err := u.Uint8()
	if err != nil {
		return zero, err
	}
	tlen, err := u.Uint8()
	if err != nil {
		return zero, err
	}
	tag, err := u.Bytes(int(tlen))
	if err != nil {
		return zero, err
	}
	val, err := u.Bytes(end - u.Off())
	if err != nil {
		return zero, err
	}
	cp := make([]byte, len(val))
	copy(cp, val)
	return CAA{flags: flags, tag: string(tag), value: cp}, nil
}
