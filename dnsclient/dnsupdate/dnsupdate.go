// Package dnsupdate constructs and sends RFC 2136 dynamic update
// messages. The wire-level encoding reuses the standard sections — ZONE
// in the place of QUESTION, PREREQUISITE in place of ANSWER, UPDATE in
// place of AUTHORITY — with the opcode set to UPDATE (5).
//
// This package focuses on the most commonly used prerequisite forms and
// update operations. Class-specific value-match prerequisites and CNAME
// safety checks are out of scope for this version.
package dnsupdate

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient/transport"
	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/lestrrat-go/acidns/tsig"
)

// Builder constructs an UPDATE message piece-by-piece.
type Builder struct {
	zone    dnsname.Name
	prereqs []dnsmsg.Record
	updates []dnsmsg.Record
}

// NewBuilder returns a Builder targeting the named zone.
func NewBuilder(zone dnsname.Name) *Builder { return &Builder{zone: zone} }

// AddRRset queues a record-set addition (RFC 2136 §2.5.1).
func (b *Builder) AddRRset(rec dnsmsg.Record) *Builder {
	b.updates = append(b.updates, rec)
	return b
}

// DeleteRRset queues the removal of every record at name with the given
// type (RFC 2136 §2.5.2): CLASS=ANY, TTL=0, empty rdata.
func (b *Builder) DeleteRRset(name dnsname.Name, t rrtype.Type) *Builder {
	b.updates = append(b.updates,
		dnsmsg.NewRecordClass(name, rrtype.ClassANY, 0, rdata.NewUnknown(t, nil)))
	return b
}

// DeleteAll queues the removal of every RRset at name (RFC 2136 §2.5.3):
// TYPE=ANY, CLASS=ANY, TTL=0, empty rdata.
func (b *Builder) DeleteAll(name dnsname.Name) *Builder {
	b.updates = append(b.updates,
		dnsmsg.NewRecordClass(name, rrtype.ClassANY, 0, rdata.NewUnknown(rrtype.ANY, nil)))
	return b
}

// DeleteRecord queues removal of one specific record (RFC 2136 §2.5.4):
// CLASS=NONE, TTL=0, original rdata.
func (b *Builder) DeleteRecord(rec dnsmsg.Record) *Builder {
	b.updates = append(b.updates,
		dnsmsg.NewRecordClass(rec.Name(), rrtype.ClassNONE, 0, rec.RData()))
	return b
}

// PrereqRRsetExists adds a prerequisite that an RRset of the given type
// is present at name (RFC 2136 §2.4.1).
func (b *Builder) PrereqRRsetExists(name dnsname.Name, t rrtype.Type) *Builder {
	b.prereqs = append(b.prereqs,
		dnsmsg.NewRecordClass(name, rrtype.ClassANY, 0, rdata.NewUnknown(t, nil)))
	return b
}

// PrereqRRsetAbsent adds a prerequisite that no RRset of the given type
// exists at name (RFC 2136 §2.4.3).
func (b *Builder) PrereqRRsetAbsent(name dnsname.Name, t rrtype.Type) *Builder {
	b.prereqs = append(b.prereqs,
		dnsmsg.NewRecordClass(name, rrtype.ClassNONE, 0, rdata.NewUnknown(t, nil)))
	return b
}

// PrereqNameInUse adds a prerequisite that name has at least one RRset
// (RFC 2136 §2.4.4).
func (b *Builder) PrereqNameInUse(name dnsname.Name) *Builder {
	b.prereqs = append(b.prereqs,
		dnsmsg.NewRecordClass(name, rrtype.ClassANY, 0, rdata.NewUnknown(rrtype.ANY, nil)))
	return b
}

// PrereqNameNotInUse adds a prerequisite that name has no RRsets
// (RFC 2136 §2.4.5).
func (b *Builder) PrereqNameNotInUse(name dnsname.Name) *Builder {
	b.prereqs = append(b.prereqs,
		dnsmsg.NewRecordClass(name, rrtype.ClassNONE, 0, rdata.NewUnknown(rrtype.ANY, nil)))
	return b
}

// Build returns the encoded UPDATE message ready for marshaling.
func (b *Builder) Build() (dnsmsg.Message, error) {
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	mb := dnsmsg.NewBuilder().
		ID(id).
		Opcode(dnsmsg.OpcodeUpdate).
		Question(dnsmsg.NewQuestion(b.zone, rrtype.SOA))
	for _, p := range b.prereqs {
		mb = mb.Answer(p)
	}
	for _, u := range b.updates {
		mb = mb.Authority(u)
	}
	return mb.Build()
}

// Send marshals the message and ships it over ex.
func (b *Builder) Send(ctx context.Context, ex transport.Exchanger) (dnsmsg.Message, error) {
	m, err := b.Build()
	if err != nil {
		return nil, err
	}
	return ex.Exchange(ctx, m)
}

// SignedWire returns the TSIG-signed wire-format bytes of the update,
// implementing RFC 3007's "Secure DNS Dynamic Update" client side. The
// caller is responsible for shipping the bytes — either by writing them
// to a UDP/TCP socket directly or by feeding them to a custom transport
// that bypasses Exchanger's automatic Marshal step.
//
// fudge is the clock-skew window the server is allowed for the
// timestamp; 5 minutes is conventional.
func (b *Builder) SignedWire(key tsig.Key, now time.Time, fudge time.Duration) ([]byte, error) {
	m, err := b.Build()
	if err != nil {
		return nil, err
	}
	wire, err := dnsmsg.Marshal(m)
	if err != nil {
		return nil, err
	}
	return tsig.Sign(wire, key, now, fudge)
}

func randomID() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}
