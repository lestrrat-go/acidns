package rdata

import (
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// Unknown is the fallback rdata for RR types this package does not parse
// natively. Its payload is exposed as opaque bytes.
//
// Unlike typed rdata, Type() reads from a per-instance field rather than
// returning a constant — Unknown spans the entire RR-type space the codec
// does not recognise. Consequently Unknown deliberately does NOT implement
// the rdata.Typed marker interface; ResolveAs[Unknown] is a compile error
// because there is no inherent rrtype to query for.
type Unknown struct {
	typ  rrtype.Type
	data []byte
}

func (u Unknown) Type() rrtype.Type     { return u.typ }
func (u Unknown) Bytes() []byte         { return u.data }
func (u Unknown) Pack(p *wirebb.Packer) { p.Raw(u.data) }

// NewUnknown returns an Unknown rdata for type t with the given raw bytes.
func NewUnknown(t rrtype.Type, data []byte) Unknown {
	cp := make([]byte, len(data))
	copy(cp, data)
	return Unknown{typ: t, data: cp}
}
