package validator

import (
	"slices"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

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
	return slices.Contains(types, t)
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
