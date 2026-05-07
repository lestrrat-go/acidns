package validator

import (
	"bytes"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// recordsOfType filters records by (type, owner). Owner match is by
// wire-form equality (case-insensitive — names are stored lowercase).
func recordsOfType(records []wire.Record, t rrtype.Type, owner wire.Name) []wire.Record {
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

// extractRRSIGs returns the RRSIG rdata payloads from records.
func extractRRSIGs(records []wire.Record) []rdata.RRSIG {
	out := make([]rdata.RRSIG, 0, len(records))
	for _, r := range records {
		s, ok := wire.RDataAs[rdata.RRSIG](r)
		if !ok {
			continue
		}
		out = append(out, s)
	}
	return out
}

// rrsigsForTypeAndOwner narrows RRSIGs to those covering t at owner.
func rrsigsForTypeAndOwner(sigs []rdata.RRSIG, t rrtype.Type, owner wire.Name) []rdata.RRSIG {
	// owner is currently unused for filtering — RRSIG does not carry the
	// covered-rrset owner, only the signer name. We keep the parameter
	// for API symmetry and future use (the resolver may pre-group records
	// by owner before invoking).
	_ = owner
	out := make([]rdata.RRSIG, 0, len(sigs))
	for _, s := range sigs {
		if s.TypeCovered() == t {
			out = append(out, s)
		}
	}
	return out
}

// bitmapHas reports whether t appears in an NSEC/NSEC3 type bitmap slice.
func bitmapHas(types []rrtype.Type, t rrtype.Type) bool {
	for _, x := range types {
		if x == t {
			return true
		}
	}
	return false
}

// allNSEC returns every NSEC record in records, regardless of owner.
func allNSEC(records []wire.Record) []wire.Record {
	out := make([]wire.Record, 0, len(records))
	for _, r := range records {
		if r.Type() == rrtype.NSEC {
			out = append(out, r)
		}
	}
	return out
}

// signerOf returns the SignerName carried by the first RRSIG in records,
// or an invalid Name if no RRSIG is present. Useful for inferring the
// authoritative zone of a response without parsing SOA records.
func signerOf(records []wire.Record) wire.Name {
	for _, r := range records {
		s, ok := wire.RDataAs[rdata.RRSIG](r)
		if ok {
			return s.SignerName()
		}
	}
	return wire.Name{}
}

// recordsOfType3 returns every NSEC3 record in records.
func recordsOfType3(records []wire.Record) []wire.Record {
	out := make([]wire.Record, 0, len(records))
	for _, r := range records {
		if r.Type() == rrtype.NSEC3 {
			out = append(out, r)
		}
	}
	return out
}

// groupRecordsByOwner partitions records by owner name. Order of returned
// groups matches first appearance.
func groupRecordsByOwner(records []wire.Record) [][]wire.Record {
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

// groupNSECByOwner partitions NSEC records by owner. Order of returned
// groups matches first appearance.
func groupNSECByOwner(records []wire.Record) [][]wire.Record {
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

// filterNSECByOwner returns NSEC records whose owner equals target.
func filterNSECByOwner(records []wire.Record, target wire.Name) []wire.Record {
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

// nameCoveredBy reports whether qname falls strictly between owner and
// next in canonical DNS name order (RFC 4034 §6.1). Wraparound at the
// zone apex (next < owner) is handled per §4.1.1.
func nameCoveredBy(qname, owner, next wire.Name) bool {
	switch {
	case canonicalNameCmp(owner, next) < 0:
		return canonicalNameCmp(owner, qname) < 0 && canonicalNameCmp(qname, next) < 0
	default:
		// Wraparound: qname > owner OR qname < next.
		return canonicalNameCmp(owner, qname) < 0 || canonicalNameCmp(qname, next) < 0
	}
}

// canonicalNameCmp implements RFC 4034 §6.1 canonical name ordering: label
// by label from the right, with bytes within each label compared
// lexicographically and "shorter prefix sorts before longer".
func canonicalNameCmp(a, b wire.Name) int {
	aLabels := collectLabels(a)
	bLabels := collectLabels(b)
	n := len(aLabels)
	if len(bLabels) < n {
		n = len(bLabels)
	}
	for i := 0; i < n; i++ {
		if c := bytes.Compare(aLabels[i], bLabels[i]); c != 0 {
			return c
		}
	}
	return len(aLabels) - len(bLabels)
}

// collectLabels returns the labels of n in root-first order (the order in
// which they are compared by RFC 4034 §6.1). The returned slices are
// freshly allocated and lowercased (Names are stored lowercase already).
func collectLabels(n wire.Name) [][]byte {
	var leafFirst [][]byte
	for l := range n.Labels() {
		cp := make([]byte, len(l))
		copy(cp, l)
		leafFirst = append(leafFirst, cp)
	}
	for i, j := 0, len(leafFirst)-1; i < j; i, j = i+1, j-1 {
		leafFirst[i], leafFirst[j] = leafFirst[j], leafFirst[i]
	}
	return leafFirst
}
