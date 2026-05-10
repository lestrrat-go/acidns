package validator

import (
	"fmt"

	"github.com/lestrrat-go/acidns/dnssec/validator/validatorbb"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
)

// Anchor is a DNSSEC trust anchor: the apex of a zone the validator is
// configured to trust together with the DS records that authenticate its
// DNSKEY set. Multiple DS records cover algorithm rollovers at the parent
// (e.g. the root has two KSKs during a rollover). Construct via
// [NewAnchor]; the zero Anchor is invalid (use [Anchor.IsValid] to
// distinguish).
type Anchor struct {
	name wire.Name
	dss  []rdata.DS
}

// Name returns the apex of the trusted zone.
func (a Anchor) Name() wire.Name { return a.name }

// DSs returns the DS records that authenticate any DNSKEY claimed by
// the zone. Aliases internal storage — callers MUST NOT mutate the
// returned slice (consistent with the module-wide alias-by-default
// accessor semantics).
func (a Anchor) DSs() []rdata.DS { return a.dss }

// IsValid reports whether a was constructed via [NewAnchor] (i.e.
// has a valid name and at least one DS record).
func (a Anchor) IsValid() bool { return a.name.IsValid() && len(a.dss) > 0 }

// NewAnchor returns an Anchor with the supplied name and DS records.
// An empty DS list is rejected because an anchor without DS material
// cannot authenticate anything.
func NewAnchor(name wire.Name, dss ...rdata.DS) (Anchor, error) {
	if !name.IsValid() {
		return Anchor{}, fmt.Errorf("validator: invalid anchor name")
	}
	if len(dss) == 0 {
		return Anchor{}, fmt.Errorf("validator: anchor %s has no DS records", name)
	}
	return Anchor{name: name, dss: dss}, nil
}

// IANARootKSK2017DS returns the DS record for the 2017 root KSK
// (key tag 20326). Provided as a building block so callers composing
// their own anchor (e.g. with custom NTAs or extra anchors) can
// reference the IANA-published material directly.
func IANARootKSK2017DS() rdata.DS {
	digest := validatorbb.MustHex("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D")
	return rdata.NewDS(20326, rdata.AlgRSASHA256, rdata.DigestSHA256, digest)
}

// IANARootKSK2024DS returns the DS record for the 2024 root KSK
// (key tag 38696). Pinned at the values published in the IANA
// root-anchors.xml file.
//
// Last verified: 2024-12-15 against
// https://data.iana.org/root-anchors/root-anchors.xml.
func IANARootKSK2024DS() rdata.DS {
	digest := validatorbb.MustHex("683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16")
	return rdata.NewDS(38696, rdata.AlgRSASHA256, rdata.DigestSHA256, digest)
}

// IANARootAnchor returns the IANA root KSK trust anchor pinned at the
// values published in the root-anchors.xml file. The returned anchor
// includes BOTH KSK-2017 (key tag 20326) and KSK-2024 (key tag 38696)
// so the validator continues to function across the rollover from
// KSK-2017 to KSK-2024.
//
// When ICANN publishes future KSK rollover material, callers SHOULD
// either update this library or compose their own anchor via
// [NewAnchor] using [IANARootKSK2017DS] / [IANARootKSK2024DS] /
// future helpers and an RFC 5011-managed local copy.
//
// The value is provided as a convenience for clients that just want
// "DNSSEC works against the live root" without shipping their own
// RFC 5011 trust-anchor file.
func IANARootAnchor() Anchor {
	root := wire.RootName()
	a, err := NewAnchor(root, IANARootKSK2017DS(), IANARootKSK2024DS())
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
		if !validatorbb.NameSuffixEqualOrSubdomain(qname, a.Name()) {
			continue
		}
		nl := a.Name().NumLabels()
		if nl > bestLabels {
			bestLabels = nl
			best = a
		}
	}
	return best, best.IsValid()
}
