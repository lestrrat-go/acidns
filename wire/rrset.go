package wire

import (
	"fmt"
	"time"

	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// RRset is a resource record set per RFC 2181 §5: the set of records sharing
// the same owner name, class, and type. A well-formed RRset has all members
// agree on TTL (RFC 2181 §5.2 — receivers MUST treat the lowest TTL as the
// authoritative one); the type allows construction of mixed-TTL sets but
// NormalizeTTL exposes the harmonised value.
//
// RRset members preserve insertion order. Order has no protocol significance
// inside an RRset (RFC 2181 §5.1) but is preserved so callers retain
// stable iteration.
type RRset interface {
	Name() wirebb.Name
	Type() rrtype.Type
	Class() rrtype.Class
	TTL() time.Duration
	Records() []Record
	Len() int
}

type rrset struct {
	name    wirebb.Name
	typ     rrtype.Type
	class   rrtype.Class
	ttl     time.Duration
	records []Record
}

func (s rrset) Name() wirebb.Name   { return s.name }
func (s rrset) Type() rrtype.Type   { return s.typ }
func (s rrset) Class() rrtype.Class { return s.class }
func (s rrset) TTL() time.Duration  { return s.ttl }
func (s rrset) Records() []Record   { return s.records }
func (s rrset) Len() int            { return len(s.records) }

// NewRRset returns an RRset built from the supplied records. All records
// must share owner name (case-insensitive equality), class, and type. The
// RRset TTL is the minimum TTL among the inputs (RFC 2181 §5.2). Empty
// input is rejected.
func NewRRset(records ...Record) (RRset, error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("%w: RRset requires at least one record", ErrInvalidMessage)
	}
	first := records[0]
	minTTL := first.TTL()
	for i, r := range records[1:] {
		if !first.Name().Equal(r.Name()) {
			return nil, fmt.Errorf("%w: RRset record %d name mismatch (%s vs %s)",
				ErrInvalidMessage, i+1, first.Name(), r.Name())
		}
		if first.Class() != r.Class() {
			return nil, fmt.Errorf("%w: RRset record %d class mismatch", ErrInvalidMessage, i+1)
		}
		if first.Type() != r.Type() {
			return nil, fmt.Errorf("%w: RRset record %d type mismatch (%s vs %s)",
				ErrInvalidMessage, i+1, first.Type(), r.Type())
		}
		if r.TTL() < minTTL {
			minTTL = r.TTL()
		}
	}
	cp := make([]Record, len(records))
	copy(cp, records)
	return rrset{
		name:    first.Name(),
		typ:     first.Type(),
		class:   first.Class(),
		ttl:     minTTL,
		records: cp,
	}, nil
}

// NewRRsetFromRDatas is a convenience constructor that builds an RRset from
// a list of rdata payloads sharing a common owner name, class, type, and
// TTL.
func NewRRsetFromRDatas(name wirebb.Name, class rrtype.Class, ttl time.Duration, rds ...rdata.RData) (RRset, error) {
	if len(rds) == 0 {
		return nil, fmt.Errorf("%w: RRset requires at least one rdata", ErrInvalidMessage)
	}
	typ := rds[0].Type()
	records := make([]Record, len(rds))
	for i, rd := range rds {
		if rd.Type() != typ {
			return nil, fmt.Errorf("%w: RRset rdata %d type mismatch (%s vs %s)",
				ErrInvalidMessage, i, typ, rd.Type())
		}
		records[i] = NewRecordClass(name, class, ttl, rd)
	}
	return rrset{name: name, typ: typ, class: class, ttl: ttl, records: records}, nil
}

// GroupRecords partitions records into RRsets keyed by (name, class, type).
// Order of the returned RRsets matches the order of first appearance. RRsets
// with mixed TTLs harmonise to the minimum per RFC 2181 §5.2.
func GroupRecords(records []Record) ([]RRset, error) {
	type key struct {
		name  string
		class rrtype.Class
		typ   rrtype.Type
	}
	indexByKey := make(map[key]int)
	var groups [][]Record
	for _, r := range records {
		// Names are stored in canonical lowercase wire form, so the
		// String() representation is a stable case-insensitive key.
		k := key{name: r.Name().String(), class: r.Class(), typ: r.Type()}
		idx, ok := indexByKey[k]
		if !ok {
			indexByKey[k] = len(groups)
			groups = append(groups, []Record{r})
			continue
		}
		groups[idx] = append(groups[idx], r)
	}
	out := make([]RRset, 0, len(groups))
	for _, g := range groups {
		s, err := NewRRset(g...)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}
