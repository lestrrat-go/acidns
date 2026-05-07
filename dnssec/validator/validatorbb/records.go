package validatorbb

import (
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// RecordsOfType filters records by (type, owner). Owner match is by
// wire-form equality (case-insensitive — names are stored lowercase).
func RecordsOfType(records []wire.Record, t rrtype.Type, owner wire.Name) []wire.Record {
	out := make([]wire.Record, 0, len(records))
	for _, r := range records {
		if r.Type() != t {
			continue
		}
		if !r.Name().Equal(owner) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// SignerOf returns the SignerName carried by the first RRSIG in records,
// or an invalid Name if no RRSIG is present. Useful for inferring the
// authoritative zone of a response without parsing SOA records.
func SignerOf(records []wire.Record) wire.Name {
	for _, r := range records {
		s, ok := wire.RDataAs[rdata.RRSIG](r)
		if ok {
			return s.SignerName()
		}
	}
	return wire.Name{}
}

// GroupRecordsByOwner partitions records by owner name. Order of returned
// groups matches first appearance of each owner in records.
func GroupRecordsByOwner(records []wire.Record) [][]wire.Record {
	idx := make(map[string]int)
	var out [][]wire.Record
	for _, r := range records {
		k := r.Name().String()
		i, ok := idx[k]
		if !ok {
			idx[k] = len(out)
			out = append(out, []wire.Record{r})
			continue
		}
		out[i] = append(out[i], r)
	}
	return out
}

// FilterNSECByOwner returns NSEC records whose owner equals target. Other
// record types and other owners are dropped.
func FilterNSECByOwner(records []wire.Record, target wire.Name) []wire.Record {
	out := make([]wire.Record, 0, len(records))
	for _, r := range records {
		if r.Type() != rrtype.NSEC {
			continue
		}
		if r.Name().Equal(target) {
			out = append(out, r)
		}
	}
	return out
}
