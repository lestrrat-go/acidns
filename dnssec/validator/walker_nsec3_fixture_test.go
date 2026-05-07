package validator_test

import (
	"context"
	"time"

	"github.com/lestrrat-go/acidns/dnssec/validator"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// nsec3Mode flips a signedZone into NSEC3 denial mode. salt and iterations
// are zone-wide. optOut is on a per-record basis but for fixture purposes
// we apply it to all NSEC3s emitted by the zone.
type nsec3Mode struct {
	iterations uint16
	salt       []byte
	optOut     bool
}


// nsec3Source serves the same data as fixtureSource but renders denial
// answers using NSEC3 closest-encloser proofs.
type nsec3Source struct {
	zones []*signedZone
	mode  nsec3Mode
}

func newNSEC3Source(mode nsec3Mode, zones ...*signedZone) *nsec3Source {
	return &nsec3Source{zones: zones, mode: mode}
}

func (s *nsec3Source) Lookup(_ context.Context, qname wire.Name, qtype rrtype.Type) (wire.Message, error) {
	var zone *signedZone
	if qtype == rrtype.DS {
		zone = s.findParentZone(qname)
	} else {
		zone = s.findZone(qname)
	}
	if zone == nil {
		return wire.NewBuilder().
			ID(1).
			Response(true).
			RCODE(wire.RCODENXDomain).
			Question(wire.NewQuestion(qname, qtype)).
			Build()
	}
	if rrs := zone.recordsAt(qname, qtype); len(rrs) > 0 {
		return zone.buildAnswer(qname, qtype, rrs)
	}
	if zone.nameExists(qname) {
		return s.buildNoDataNSEC3(zone, qname, qtype)
	}
	return s.buildNXDOMAINNSEC3(zone, qname, qtype)
}

func (s *nsec3Source) findZone(qname wire.Name) *signedZone {
	var best *signedZone
	bestLabels := -1
	for _, z := range s.zones {
		if !nameSubdomainOrEqual(qname, z.apex) {
			continue
		}
		nl := z.apex.NumLabels()
		if nl > bestLabels {
			bestLabels = nl
			best = z
		}
	}
	return best
}

func (s *nsec3Source) findParentZone(qname wire.Name) *signedZone {
	var best *signedZone
	bestLabels := -1
	for _, z := range s.zones {
		if z.apex.Equal(qname) {
			continue
		}
		if !nameSubdomainOrEqual(qname, z.apex) {
			continue
		}
		nl := z.apex.NumLabels()
		if nl > bestLabels {
			bestLabels = nl
			best = z
		}
	}
	return best
}

func (s *nsec3Source) buildNoDataNSEC3(z *signedZone, qname wire.Name, qtype rrtype.Type) (wire.Message, error) {
	types := z.typesAt(qname)
	hasNSEC3 := false
	hasRRSIG := false
	for _, t := range types {
		if t == rrtype.NSEC3 {
			hasNSEC3 = true
		}
		if t == rrtype.RRSIG {
			hasRRSIG = true
		}
	}
	if !hasNSEC3 {
		types = append(types, rrtype.NSEC3)
	}
	if !hasRRSIG {
		types = append(types, rrtype.RRSIG)
	}
	owner := s.nsec3Owner(z, qname)
	next := bumpHash(s.hash(qname))
	flags := uint8(0)
	if s.mode.optOut {
		flags |= 0x01
	}
	rec := wire.NewRecord(owner, time.Hour,
		rdata.NewNSEC3(1, flags, s.mode.iterations, s.mode.salt, next, types))
	sig := z.signRRset([]wire.Record{rec})
	return wire.NewBuilder().
		ID(1).
		Response(true).
		RCODE(wire.RCODENoError).
		Question(wire.NewQuestion(qname, qtype)).
		Authority(rec).
		Authority(wire.NewRecord(owner, time.Hour, sig)).
		Build()
}

func (s *nsec3Source) buildNXDOMAINNSEC3(z *signedZone, qname wire.Name, qtype rrtype.Type) (wire.Message, error) {
	// Closest-encloser proof requires three NSEC3s:
	//   1. Matching NSEC3 at closest encloser.
	//   2. Covering NSEC3 for next-closer name (one label below encloser).
	//   3. Covering NSEC3 for *.encloser.
	encloser := s.findClosestEncloser(z, qname)
	nextCloser := nextCloser(qname, encloser)
	wildcard, _ := wireWildcardOf(encloser)

	flags := uint8(0)
	if s.mode.optOut {
		flags |= 0x01
	}

	// (1) matching NSEC3 at encloser.
	encOwner := s.nsec3Owner(z, encloser)
	encTypes := z.typesAt(encloser)
	if !contains(encTypes, rrtype.NSEC3) {
		encTypes = append(encTypes, rrtype.NSEC3)
	}
	if !contains(encTypes, rrtype.RRSIG) {
		encTypes = append(encTypes, rrtype.RRSIG)
	}
	encRec := wire.NewRecord(encOwner, time.Hour,
		rdata.NewNSEC3(1, flags, s.mode.iterations, s.mode.salt,
			bumpHash(s.hash(encloser)), encTypes))
	encSig := z.signRRset([]wire.Record{encRec})

	// (2) covering NSEC3 for next-closer.
	ncOwner, ncRec := s.coveringNSEC3(z, nextCloser, flags)

	// (3) covering NSEC3 for *.encloser.
	wcOwner, wcRec := s.coveringNSEC3(z, wildcard, flags)

	b := wire.NewBuilder().
		ID(1).
		Response(true).
		RCODE(wire.RCODENXDomain).
		Question(wire.NewQuestion(qname, qtype))
	for _, p := range []struct {
		owner wire.Name
		rec   wire.Record
	}{
		{encOwner, encRec},
		{ncOwner, ncRec},
		{wcOwner, wcRec},
	} {
		b.Authority(p.rec)
	}
	// Sign each NSEC3 rrset; in the fixture each NSEC3 is its own rrset
	// (distinct owner names).
	b.Authority(wire.NewRecord(encOwner, time.Hour, encSig))
	b.Authority(wire.NewRecord(ncOwner, time.Hour, z.signRRset([]wire.Record{ncRec})))
	b.Authority(wire.NewRecord(wcOwner, time.Hour, z.signRRset([]wire.Record{wcRec})))
	return b.Build()
}

func (s *nsec3Source) coveringNSEC3(z *signedZone, name wire.Name, flags uint8) (wire.Name, wire.Record) {
	target := s.hash(name)
	// Synthesise an owner-hash strictly below target and a next-hash
	// strictly above. This is sufficient for the validator's interval check.
	ownerHash := bumpHashDown(target)
	nextHash := bumpHash(target)
	owner := s.synthOwner(z, ownerHash)
	rec := wire.NewRecord(owner, time.Hour,
		rdata.NewNSEC3(1, flags, s.mode.iterations, s.mode.salt, nextHash, nil))
	return owner, rec
}

func (s *nsec3Source) hash(name wire.Name) []byte {
	return validator.NSEC3HashForTest(name, s.mode.salt, s.mode.iterations)
}

func (s *nsec3Source) nsec3Owner(z *signedZone, name wire.Name) wire.Name {
	return s.synthOwner(z, s.hash(name))
}

func (s *nsec3Source) synthOwner(z *signedZone, hash []byte) wire.Name {
	label := validator.Base32HexEncodeForTest(hash)
	labels := []string{label}
	for l := range z.apex.Labels() {
		labels = append(labels, string(l))
	}
	out, _ := wire.NameFromLabels(labels...)
	return out
}

func (s *nsec3Source) findClosestEncloser(z *signedZone, qname wire.Name) wire.Name {
	cur := qname
	for {
		parent, ok := cur.Parent()
		if !ok {
			return z.apex
		}
		if z.nameExists(parent) || parent.Equal(z.apex) {
			return parent
		}
		cur = parent
	}
}

// nextCloser returns the next-closer name (RFC 5155 §1.3): one label deeper
// than encloser toward qname.
func nextCloser(qname, encloser wire.Name) wire.Name {
	cur := qname
	for cur.NumLabels() > encloser.NumLabels()+1 {
		parent, ok := cur.Parent()
		if !ok {
			return cur
		}
		cur = parent
	}
	return cur
}

func wireWildcardOf(encloser wire.Name) (wire.Name, error) {
	labels := []string{"*"}
	for l := range encloser.Labels() {
		labels = append(labels, string(l))
	}
	return wire.NameFromLabels(labels...)
}

// bumpHash returns hash + 1 in big-endian, with overflow handled by wrapping.
func bumpHash(h []byte) []byte {
	cp := make([]byte, len(h))
	copy(cp, h)
	for i := len(cp) - 1; i >= 0; i-- {
		cp[i]++
		if cp[i] != 0 {
			return cp
		}
	}
	// Overflow → all zero already.
	return cp
}

// bumpHashDown returns hash - 1 (clamped at all-zero).
func bumpHashDown(h []byte) []byte {
	cp := make([]byte, len(h))
	copy(cp, h)
	for i := len(cp) - 1; i >= 0; i-- {
		if cp[i] > 0 {
			cp[i]--
			return cp
		}
		cp[i] = 0xff
	}
	return cp
}

func contains(t []rrtype.Type, want rrtype.Type) bool {
	for _, x := range t {
		if x == want {
			return true
		}
	}
	return false
}

