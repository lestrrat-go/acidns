package validator

import (
	"fmt"
	"strings"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
)

// Anchor is a DNSSEC trust anchor: the apex of a zone the validator is
// configured to trust together with the DS records that authenticate its
// DNSKEY set. Multiple DS records cover algorithm rollovers at the parent
// (e.g. the root has two KSKs during a rollover).
type Anchor interface {
	// Name returns the apex of the trusted zone.
	Name() wire.Name
	// DSs returns the DS records that authenticate any DNSKEY claimed by
	// the zone. The slice MUST NOT be mutated.
	DSs() []rdata.DS
}

type anchor struct {
	name wire.Name
	dss  []rdata.DS
}

func (a anchor) Name() wire.Name   { return a.name }
func (a anchor) DSs() []rdata.DS   { return a.dss }

// NewAnchor returns an Anchor with the supplied name and DS records. The DS
// list is copied; an empty list is rejected because an anchor without DS
// material cannot authenticate anything.
func NewAnchor(name wire.Name, dss ...rdata.DS) (Anchor, error) {
	if !name.IsValid() {
		return nil, fmt.Errorf("validator: invalid anchor name")
	}
	if len(dss) == 0 {
		return nil, fmt.Errorf("validator: anchor %s has no DS records", name)
	}
	cp := append([]rdata.DS(nil), dss...)
	return anchor{name: name, dss: cp}, nil
}

// IANARootAnchor returns the IANA root KSK trust anchor pinned at the
// values published in the root-anchors.xml file (KSK-2017, key tag 20326,
// SHA-256). When the root rolls a new KSK, callers MUST update or replace
// this anchor; the value is provided as a convenience for clients that
// just want "DNSSEC works against the live root" without shipping their
// own RFC 5011 trust-anchor file.
//
// Last verified: 2024-01-22 against
// https://data.iana.org/root-anchors/root-anchors.xml — only the SHA-256
// digest is encoded here. KSK-2024, when published, will need to be added.
func IANARootAnchor() Anchor {
	root := wire.RootName()
	digest := mustHex("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D")
	ds := rdata.NewDS(20326, rdata.AlgRSASHA256, rdata.DigestSHA256, digest)
	a, err := NewAnchor(root, ds)
	if err != nil {
		panic(err) // unreachable
	}
	return a
}

// closestAnchor returns the configured anchor whose name is the longest
// suffix of qname. ok=false if no anchor matches.
func closestAnchor(anchors []Anchor, qname wire.Name) (Anchor, bool) {
	var best Anchor
	bestLabels := -1
	for _, a := range anchors {
		if !nameSuffixEqualOrSubdomain(qname, a.Name()) {
			continue
		}
		nl := a.Name().NumLabels()
		if nl > bestLabels {
			bestLabels = nl
			best = a
		}
	}
	return best, best != nil
}

// nameSuffixEqualOrSubdomain reports whether sub equals parent or is a
// strict subdomain of parent. Comparison is case-insensitive on the
// presentation form (names are stored lowercase so this is also wire-equal).
func nameSuffixEqualOrSubdomain(sub, parent wire.Name) bool {
	if sub.Equal(parent) {
		return true
	}
	subStr := strings.ToLower(sub.String())
	parentStr := strings.ToLower(parent.String())
	if parentStr == "." {
		return true
	}
	if !strings.HasSuffix(subStr, "."+parentStr) {
		return false
	}
	return true
}

func mustHex(s string) []byte {
	out := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		hi := hexDigit(s[i])
		lo := hexDigit(s[i+1])
		if hi < 0 || lo < 0 {
			panic("validator: invalid hex literal: " + s)
		}
		out[i/2] = byte(hi<<4 | lo)
	}
	return out
}

func hexDigit(b byte) int {
	switch {
	case b >= '0' && b <= '9':
		return int(b - '0')
	case b >= 'a' && b <= 'f':
		return int(b-'a') + 10
	case b >= 'A' && b <= 'F':
		return int(b-'A') + 10
	}
	return -1
}
