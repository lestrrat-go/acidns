package rdata

import (
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// Unknown is the fallback rdata for RR types this package does not parse
// natively. Its payload is exposed as opaque bytes.
type Unknown interface {
	RData
	Bytes() []byte
}

type unknown struct {
	typ  rrtype.Type
	data []byte
}

func (u *unknown) Type() rrtype.Type     { return u.typ }
func (u *unknown) Bytes() []byte         { return u.data }
func (u *unknown) Pack(p *wirebb.Packer) { p.Raw(u.data) }

// NewUnknown returns an Unknown rdata for type t with the given raw bytes.
func NewUnknown(t rrtype.Type, data []byte) Unknown {
	cp := make([]byte, len(data))
	copy(cp, data)
	return &unknown{typ: t, data: cp}
}
