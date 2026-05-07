package wire

import (
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// ErrInvalidMessage is returned when a DNS message fails to encode or decode.
var ErrInvalidMessage = errors.New("dnsmsg: invalid message")

// Record is a resource record: name, type/class, TTL, and a typed rdata.
type Record interface {
	Name() wirebb.Name
	Type() rrtype.Type
	Class() rrtype.Class
	TTL() time.Duration
	RData() rdata.RData
}

type record struct {
	name  wirebb.Name
	class rrtype.Class
	ttl   time.Duration
	rd    rdata.RData
}

func (r record) Name() wirebb.Name   { return r.name }
func (r record) Type() rrtype.Type   { return r.rd.Type() }
func (r record) Class() rrtype.Class { return r.class }
func (r record) TTL() time.Duration  { return r.ttl }
func (r record) RData() rdata.RData  { return r.rd }

// NewRecord returns a Record with class IN.
func NewRecord(name wirebb.Name, ttl time.Duration, rd rdata.RData) Record {
	return record{name: name, class: rrtype.ClassIN, ttl: ttl, rd: rd}
}

// NewRecordClass returns a Record with the given class.
func NewRecordClass(name wirebb.Name, class rrtype.Class, ttl time.Duration, rd rdata.RData) Record {
	return record{name: name, class: class, ttl: ttl, rd: rd}
}

// RDataAs asserts rec.RData() to T iff rec.Type() == t. The Type() check
// MUST come before the assertion because rdata interface satisfaction is
// structural — rdata.A and rdata.AAAA share a method set, rdata.CNAME and
// rdata.SVCB share Target(), etc. Callers MUST pass the rrtype.Type that
// corresponds to T (e.g. rdata.MX paired with rrtype.MX).
//
// Returns the zero T and false if rec.Type() != t or the assertion fails.
func RDataAs[T rdata.RData](rec Record, t rrtype.Type) (T, bool) {
	var zero T
	if rec.Type() != t {
		return zero, false
	}
	v, ok := rec.RData().(T)
	if !ok {
		return zero, false
	}
	return v, true
}

func packRecord(p *wirebb.Packer, r Record) error {
	p.Name(r.Name())
	p.Uint16(uint16(r.Type()))
	p.Uint16(uint16(r.Class()))
	p.Uint32(uint32(r.TTL() / time.Second))

	// rdlength back-fill: write a placeholder, pack rdata, patch length.
	rdlenAt := p.Len()
	p.Uint16(0)
	startRD := p.Len()
	r.RData().Pack(p)
	endRD := p.Len()
	rdlen := endRD - startRD
	if rdlen > 0xffff {
		return fmt.Errorf("%w: rdata too large for type %s", ErrInvalidMessage, r.Type())
	}
	buf := p.Bytes()
	buf[rdlenAt] = byte(rdlen >> 8)
	buf[rdlenAt+1] = byte(rdlen)
	return nil
}

func unpackRecord(u *wirebb.Unpacker) (Record, error) {
	n, err := u.Name()
	if err != nil {
		return nil, err
	}
	t16, err := u.Uint16()
	if err != nil {
		return nil, err
	}
	c16, err := u.Uint16()
	if err != nil {
		return nil, err
	}
	ttl, err := u.Uint32()
	if err != nil {
		return nil, err
	}
	rdlen, err := u.Uint16()
	if err != nil {
		return nil, err
	}
	rd, err := rdata.Unpack(rrtype.Type(t16), u, int(rdlen))
	if err != nil {
		return nil, err
	}
	return record{
		name:  n,
		class: rrtype.Class(c16),
		ttl:   time.Duration(ttl) * time.Second,
		rd:    rd,
	}, nil
}
