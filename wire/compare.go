package wire

import (
	"bytes"
	"slices"

	"github.com/lestrrat-go/acidns/wire/rdata"
)

// SortRecords sorts s in place into RFC 4034 §6 canonical order: by owner
// name (lowercased wire form), then type, then class, then rdata bytes.
// Record TTLs are ignored — two records with identical (name, type, class,
// rdata) and different TTLs sort as equal here.
//
// SortRecords is intended for canonicalisation pre-passes (ZONEMD,
// signature input prep, message diffing). It is NOT a stable sort across
// releases of the rdata codec — if rdata.Pack changes its byte layout for
// a given type, the resulting order may change. For DNSSEC signing, use a
// purpose-built helper instead.
func SortRecords(s []Record) {
	slices.SortFunc(s, compareRecords)
}

func compareRecords(a, b Record) int {
	if c := bytes.Compare(a.Name().AppendWire(nil), b.Name().AppendWire(nil)); c != 0 {
		return c
	}
	if a.Type() != b.Type() {
		if a.Type() < b.Type() {
			return -1
		}
		return 1
	}
	if a.Class() != b.Class() {
		if a.Class() < b.Class() {
			return -1
		}
		return 1
	}
	return bytes.Compare(rdata.Pack(a.RData()), rdata.Pack(b.RData()))
}

// QuestionsMatch reports whether a and b carry the same question
// section (count, name, type, class). Name comparison is
// case-insensitive in line with RFC 4343.
//
// Use this to validate a response against the request that triggered
// it: RFC 5452 §9.2 makes ID-only validation insufficient against
// Kaminsky-style spoofing, since the 16-bit transaction ID can be
// guessed at scale.
func QuestionsMatch(a, b Message) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return questionsEqual(a.Questions(), b.Questions())
}

// MessageEqual reports whether a and b are semantically equivalent. The
// comparison is order-insensitive within each section: answers,
// authorities, additionals, and EDNS options are sorted before being
// compared, so a server that emits the same record set in a different
// order is reported equal. ID and section flags must match exactly. TTLs
// are compared as part of each record.
//
// Use it for tests and diff tools; do NOT use it as a security-relevant
// equality (it doesn't check the OPT pseudo-RR's flags beyond what's
// covered by EDNS()).
func MessageEqual(a, b Message) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if a.ID() != b.ID() || a.Flags() != b.Flags() {
		return false
	}
	if !questionsEqual(a.Questions(), b.Questions()) {
		return false
	}
	if !recordsSectionEqual(a.Answers(), b.Answers()) ||
		!recordsSectionEqual(a.Authorities(), b.Authorities()) ||
		!recordsSectionEqual(a.Additionals(), b.Additionals()) {
		return false
	}
	return ednsEqual(a, b)
}

func questionsEqual(a, b []Question) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Name().Equal(b[i].Name()) || a[i].Type() != b[i].Type() || a[i].Class() != b[i].Class() {
			return false
		}
	}
	return true
}

func recordsSectionEqual(a, b []Record) bool {
	if len(a) != len(b) {
		return false
	}
	aa := append([]Record(nil), a...)
	bb := append([]Record(nil), b...)
	SortRecords(aa)
	SortRecords(bb)
	for i := range aa {
		if !recordEqual(aa[i], bb[i]) {
			return false
		}
	}
	return true
}

func recordEqual(a, b Record) bool {
	if !a.Name().Equal(b.Name()) || a.Type() != b.Type() || a.Class() != b.Class() {
		return false
	}
	if a.TTL() != b.TTL() {
		return false
	}
	return bytes.Equal(rdata.Pack(a.RData()), rdata.Pack(b.RData()))
}

func ednsEqual(a, b Message) bool {
	ea, oka := a.EDNS()
	eb, okb := b.EDNS()
	if oka != okb {
		return false
	}
	if !oka {
		return true
	}
	if ea == nil || eb == nil {
		return ea == eb
	}
	if ea.UDPSize() != eb.UDPSize() ||
		ea.ExtendedRCODE() != eb.ExtendedRCODE() ||
		ea.Version() != eb.Version() ||
		ea.DO() != eb.DO() {
		return false
	}
	oa := ea.Options()
	ob := eb.Options()
	if len(oa) != len(ob) {
		return false
	}
	keyed := func(opts []EDNSOption) []EDNSOption {
		cp := append([]EDNSOption(nil), opts...)
		slices.SortFunc(cp, func(x, y EDNSOption) int {
			if x.Code() != y.Code() {
				if x.Code() < y.Code() {
					return -1
				}
				return 1
			}
			return bytes.Compare(x.Data(), y.Data())
		})
		return cp
	}
	sa := keyed(oa)
	sb := keyed(ob)
	for i := range sa {
		if sa[i].Code() != sb[i].Code() || !bytes.Equal(sa[i].Data(), sb[i].Data()) {
			return false
		}
	}
	return true
}
