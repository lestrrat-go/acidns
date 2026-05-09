// Package update constructs RFC 2136 dynamic update messages. The
// wire-level encoding reuses the standard sections — ZONE in the place of
// QUESTION, PREREQUISITE in place of ANSWER, UPDATE in place of AUTHORITY —
// with the opcode set to UPDATE (5).
//
// Builder.Build returns a wire.Message ready for shipping over a
// acidns.Exchanger or signing via tsig.SignMessage.
//
// This package focuses on the most commonly used prerequisite forms and
// update operations. Class-specific value-match prerequisites and CNAME
// safety checks are out of scope for this version.
package update

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// Builder constructs an UPDATE message piece-by-piece.
type Builder struct {
	zone    wire.Name
	prereqs []wire.Record
	updates []wire.Record
}

// NewBuilder returns a Builder targeting the named zone.
func NewBuilder(zone wire.Name) *Builder { return &Builder{zone: zone} }

// AddRRset queues a record-set addition (RFC 2136 §2.5.1).
func (b *Builder) AddRRset(rec wire.Record) *Builder {
	b.updates = append(b.updates, rec)
	return b
}

// DeleteRRset queues the removal of every record at name with the given
// type (RFC 2136 §2.5.2): CLASS=ANY, TTL=0, empty rdata.
func (b *Builder) DeleteRRset(name wire.Name, t rrtype.Type) *Builder {
	b.updates = append(b.updates,
		wire.NewRecordClass(name, rrtype.ClassANY, 0, rdata.NewUnknown(t, nil)))
	return b
}

// DeleteAll queues the removal of every RRset at name (RFC 2136 §2.5.3):
// TYPE=ANY, CLASS=ANY, TTL=0, empty rdata.
func (b *Builder) DeleteAll(name wire.Name) *Builder {
	b.updates = append(b.updates,
		wire.NewRecordClass(name, rrtype.ClassANY, 0, rdata.NewUnknown(rrtype.ANY, nil)))
	return b
}

// DeleteRecord queues removal of one specific record (RFC 2136 §2.5.4):
// CLASS=NONE, TTL=0, original rdata.
func (b *Builder) DeleteRecord(rec wire.Record) *Builder {
	b.updates = append(b.updates,
		wire.NewRecordClass(rec.Name(), rrtype.ClassNONE, 0, rec.RData()))
	return b
}

// PrereqRRsetExists adds a prerequisite that an RRset of the given type
// is present at name (RFC 2136 §2.4.1).
func (b *Builder) PrereqRRsetExists(name wire.Name, t rrtype.Type) *Builder {
	b.prereqs = append(b.prereqs,
		wire.NewRecordClass(name, rrtype.ClassANY, 0, rdata.NewUnknown(t, nil)))
	return b
}

// PrereqRRsetAbsent adds a prerequisite that no RRset of the given type
// exists at name (RFC 2136 §2.4.3).
func (b *Builder) PrereqRRsetAbsent(name wire.Name, t rrtype.Type) *Builder {
	b.prereqs = append(b.prereqs,
		wire.NewRecordClass(name, rrtype.ClassNONE, 0, rdata.NewUnknown(t, nil)))
	return b
}

// PrereqNameInUse adds a prerequisite that name has at least one RRset
// (RFC 2136 §2.4.4).
func (b *Builder) PrereqNameInUse(name wire.Name) *Builder {
	b.prereqs = append(b.prereqs,
		wire.NewRecordClass(name, rrtype.ClassANY, 0, rdata.NewUnknown(rrtype.ANY, nil)))
	return b
}

// PrereqNameNotInUse adds a prerequisite that name has no RRsets
// (RFC 2136 §2.4.5).
func (b *Builder) PrereqNameNotInUse(name wire.Name) *Builder {
	b.prereqs = append(b.prereqs,
		wire.NewRecordClass(name, rrtype.ClassNONE, 0, rdata.NewUnknown(rrtype.ANY, nil)))
	return b
}

// Build returns the encoded UPDATE message ready for marshaling.
func (b *Builder) Build() (wire.Message, error) {
	id, err := randomID()
	if err != nil {
		return wire.Message{}, err
	}
	mb := wire.NewBuilder().
		ID(id).
		Opcode(wire.OpcodeUpdate).
		Question(wire.NewQuestion(b.zone, rrtype.SOA))
	for _, p := range b.prereqs {
		mb = mb.Answer(p)
	}
	for _, u := range b.updates {
		mb = mb.Authority(u)
	}
	return mb.Build()
}

func randomID() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}
