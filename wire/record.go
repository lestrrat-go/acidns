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
var ErrInvalidMessage = errors.New("wire: invalid message")

// ErrInvalidTTL is returned when a record TTL is outside the
// RFC 2308 §8 valid range (0..2^31-1 seconds). Negative durations are
// rejected because they would otherwise wrap to a huge uint32 on the
// wire (claiming a ~136-year TTL); values exceeding maxRecordTTLSeconds
// are rejected because RFC 2308 §8 caps TTLs at the signed 32-bit limit.
var ErrInvalidTTL = errors.New("wire: invalid TTL")

// maxRecordTTLSeconds is the RFC 2308 §8 ceiling on a TTL value
// (signed 32-bit). Values strictly greater than this would either
// overflow or be interpreted as "expired" by RFC 2308 §8 compliant
// caches.
const maxRecordTTLSeconds = 0x7fffffff

// Record is a resource record: name, type/class, TTL, and a typed
// rdata. Value type — copy-friendly, returned by value from the
// section accessors on [Message]. The zero value's RData() is nil;
// distinguish via [Record.IsZero] when a slice may legitimately
// contain it.
type Record struct {
	name  wirebb.Name
	class rrtype.Class
	ttl   time.Duration
	rd    rdata.RData
}

// Name returns the record owner name.
func (r Record) Name() wirebb.Name { return r.name }

// Type returns the record's RR type, derived from the rdata.
func (r Record) Type() rrtype.Type {
	if r.rd == nil {
		return 0
	}
	return r.rd.Type()
}

// Class returns the record class.
func (r Record) Class() rrtype.Class { return r.class }

// TTL returns the record TTL.
func (r Record) TTL() time.Duration { return r.ttl }

// RData returns the typed rdata payload. Returns nil for the zero
// Record value.
func (r Record) RData() rdata.RData { return r.rd }

// IsZero reports whether r is the zero value (no rdata attached).
func (r Record) IsZero() bool { return r.rd == nil }

// NewRecord returns a Record with class IN.
func NewRecord(name wirebb.Name, ttl time.Duration, rd rdata.RData) Record {
	return Record{name: name, class: rrtype.ClassIN, ttl: ttl, rd: rd}
}

// NewRecordClass returns a Record with the given class.
func NewRecordClass(name wirebb.Name, class rrtype.Class, ttl time.Duration, rd rdata.RData) Record {
	return Record{name: name, class: class, ttl: ttl, rd: rd}
}

// RDataAs asserts rec.RData() to T iff rec.Type() matches T's owning
// rrtype (inferred from the zero value of T). Returns the zero T and
// false if the type check or the assertion fails.
//
// T is constrained to rdata.Typed; RDataAs[rdata.Unknown] is a compile
// error because Unknown has no inherent rrtype. Callers wanting to test
// whether a record is Unknown should type-assert rec.RData() directly.
func RDataAs[T rdata.Typed](rec Record) (T, bool) {
	var zero T
	if rec.Type() != zero.Type() {
		return zero, false
	}
	v, ok := rec.RData().(T)
	if !ok {
		return zero, false
	}
	return v, true
}

func packRecord(p *wirebb.Packer, r Record) error {
	// Validate TTL at the wire-encode boundary: a negative duration here
	// would otherwise wrap to a huge uint32 (~136-year TTL); values above
	// 2^31-1 seconds exceed the RFC 2308 §8 limit and would also wrap
	// when divided into seconds for the 32-bit wire field. This is the
	// belt-and-suspenders check that catches programmer-error TTLs even
	// when NewRecord was not validated up front.
	if r.ttl < 0 {
		return fmt.Errorf("%w: negative TTL %s for type %s", ErrInvalidTTL, r.ttl, r.Type())
	}
	if r.ttl/time.Second > maxRecordTTLSeconds {
		return fmt.Errorf("%w: TTL %s exceeds RFC 2308 §8 ceiling (2^31-1 seconds) for type %s", ErrInvalidTTL, r.ttl, r.Type())
	}
	p.Name(r.name)
	p.Uint16(uint16(r.Type()))
	p.Uint16(uint16(r.class))
	p.Uint32(uint32(r.ttl / time.Second))

	// rdlength back-fill: write a placeholder, pack rdata, patch length.
	rdlenAt := p.Len()
	p.Uint16(0)
	startRD := p.Len()
	r.rd.Pack(p)
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
		return Record{}, err
	}
	t16, err := u.Uint16()
	if err != nil {
		return Record{}, err
	}
	c16, err := u.Uint16()
	if err != nil {
		return Record{}, err
	}
	ttl, err := u.Uint32()
	if err != nil {
		return Record{}, err
	}
	// RFC 2181 §8: receivers must treat TTLs with the high bit set
	// (i.e., values >= 2^31 when read as unsigned) as zero. Without
	// this clamp, Unpack would carry a Duration that Pack later
	// refuses to re-emit per the RFC 2308 §8 ceiling.
	if ttl >= 1<<31 {
		ttl = 0
	}
	rdlen, err := u.Uint16()
	if err != nil {
		return Record{}, err
	}
	rd, err := rdata.Unpack(rrtype.Type(t16), u, int(rdlen))
	if err != nil {
		return Record{}, err
	}
	return Record{
		name:  n,
		class: rrtype.Class(c16),
		ttl:   time.Duration(ttl) * time.Second,
		rd:    rd,
	}, nil
}
