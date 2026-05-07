package validator_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnssec"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// fixtureSource serves pre-built RRsets keyed by (name, type). It mimics
// what an authoritative server would return: positive lookups return the
// stored RRset together with its RRSIG; missing-type lookups return NSEC
// from the closest signing zone that proves either the type-bit absence
// or the name's nonexistence.
type fixtureSource struct {
	zones []*signedZone
}

func newFixtureSource(zones ...*signedZone) *fixtureSource {
	return &fixtureSource{zones: zones}
}

func (s *fixtureSource) Lookup(_ context.Context, qname wire.Name, qtype rrtype.Type) (wire.Message, error) {
	// DS queries are authoritative at the PARENT zone. For all other types,
	// the deepest zone covering qname answers.
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

	// Positive answer?
	if rrs := zone.recordsAt(qname, qtype); len(rrs) > 0 {
		return zone.buildAnswer(qname, qtype, rrs)
	}

	// Type does not exist at qname → NoData.
	if zone.nameExists(qname) {
		return zone.buildNoDataNSEC(qname, qtype)
	}

	// Name does not exist → NXDOMAIN with covering NSEC.
	return zone.buildNXDOMAIN(qname, qtype)
}

func (s *fixtureSource) findZone(qname wire.Name) *signedZone {
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

// findParentZone selects the deepest zone whose apex is a STRICT ancestor
// of qname. Used for DS queries.
func (s *fixtureSource) findParentZone(qname wire.Name) *signedZone {
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

func nameSubdomainOrEqual(sub, parent wire.Name) bool {
	if sub.Equal(parent) {
		return true
	}
	cur := sub
	for {
		p, ok := cur.Parent()
		if !ok {
			return false
		}
		if p.Equal(parent) {
			return true
		}
		cur = p
	}
}

// signedZone represents an in-memory authoritative zone, keyed by
// canonical name strings. Records grouped per (name, type). Each such
// rrset is signed with the zone ZSK.
type signedZone struct {
	apex     wire.Name
	ksk      keyMat
	zsk      keyMat
	dnskeys  []rdata.DNSKEY
	dsForChild map[string][]rdata.DS // child apex name → DS records (parent perspective)
	rrsets   map[recKey][]wire.Record
	now      time.Time
	dur      time.Duration // signature validity
}

type recKey struct {
	name string
	typ  rrtype.Type
}

func newSignedZone(t *testing.T, apex wire.Name, alg rdata.DNSSECAlgorithm, now time.Time) *signedZone {
	t.Helper()
	ksk := newKey(t, alg, true)
	zsk := newKey(t, alg, false)
	z := &signedZone{
		apex:    apex,
		ksk:     ksk,
		zsk:     zsk,
		dnskeys: []rdata.DNSKEY{ksk.dnskey, zsk.dnskey},
		dsForChild: map[string][]rdata.DS{},
		rrsets:  map[recKey][]wire.Record{},
		now:     now,
		dur:     time.Hour,
	}
	return z
}

// addRR stores a record under the zone. Use addRR for any A/AAAA/NS/MX/etc.
func (z *signedZone) addRR(r wire.Record) {
	k := recKey{name: r.Name().String(), typ: r.Type()}
	z.rrsets[k] = append(z.rrsets[k], r)
}

// addDelegation registers a child zone under z. Stores the NS rrset and
// the DS rrset (using the child's KSK).
func (z *signedZone) addDelegation(t *testing.T, child *signedZone) {
	t.Helper()
	z.addRR(wire.NewRecord(child.apex, time.Hour,
		rdata.NewNS(child.apex)))
	digest, err := dnssec.DSDigest(child.apex, child.ksk.dnskey, rdata.DigestSHA256)
	require.NoError(t, err)
	ds := rdata.NewDS(dnssec.KeyTag(child.ksk.dnskey), child.ksk.dnskey.Algorithm(),
		rdata.DigestSHA256, digest)
	z.addRR(wire.NewRecord(child.apex, time.Hour, ds))
	z.dsForChild[child.apex.String()] = []rdata.DS{ds}
}

func (z *signedZone) recordsAt(name wire.Name, t rrtype.Type) []wire.Record {
	return z.rrsets[recKey{name: name.String(), typ: t}]
}

func (z *signedZone) nameExists(name wire.Name) bool {
	for k := range z.rrsets {
		if k.name == name.String() {
			return true
		}
	}
	return false
}

// buildAnswer wraps rrs in a positive response, adding a signed DNSKEY
// rrset on the side and the RRSIG over the answer. For DS queries
// originating at a child apex, this is invoked on the PARENT zone.
func (z *signedZone) buildAnswer(qname wire.Name, qtype rrtype.Type, rrs []wire.Record) (wire.Message, error) {
	sig := z.signRRset(rrs)
	b := wire.NewBuilder().
		ID(1).
		Response(true).
		RCODE(wire.RCODENoError).
		Question(wire.NewQuestion(qname, qtype))
	for _, r := range rrs {
		b.Answer(r)
	}
	b.Answer(wire.NewRecord(qname, time.Hour, sig))
	// For DNSKEY answers, attach all DNSKEYs (already in rrs since rrs IS
	// the DNSKEY rrset).
	return b.Build()
}

// buildNoDataNSEC returns a NoData response with a signed NSEC at qname.
func (z *signedZone) buildNoDataNSEC(qname wire.Name, qtype rrtype.Type) (wire.Message, error) {
	types := z.typesAt(qname)
	// Always include NSEC + RRSIG in the bitmap of the owner.
	hasNSEC := false
	hasRRSIG := false
	for _, t := range types {
		if t == rrtype.NSEC {
			hasNSEC = true
		}
		if t == rrtype.RRSIG {
			hasRRSIG = true
		}
	}
	if !hasNSEC {
		types = append(types, rrtype.NSEC)
	}
	if !hasRRSIG {
		types = append(types, rrtype.RRSIG)
	}
	next := z.nextOwnerAfter(qname)
	nsec := rdata.NewNSEC(next, types)
	rec := wire.NewRecord(qname, time.Hour, nsec)
	sig := z.signRRset([]wire.Record{rec})

	return wire.NewBuilder().
		ID(1).
		Response(true).
		RCODE(wire.RCODENoError).
		Question(wire.NewQuestion(qname, qtype)).
		Authority(rec).
		Authority(wire.NewRecord(qname, time.Hour, sig)).
		Build()
}

// buildNXDOMAIN returns NXDOMAIN with a covering NSEC.
func (z *signedZone) buildNXDOMAIN(qname wire.Name, qtype rrtype.Type) (wire.Message, error) {
	owner, next := z.coveringNSEC(qname)
	types := z.typesAt(owner)
	nsec := rdata.NewNSEC(next, types)
	rec := wire.NewRecord(owner, time.Hour, nsec)
	sig := z.signRRset([]wire.Record{rec})
	return wire.NewBuilder().
		ID(1).
		Response(true).
		RCODE(wire.RCODENXDomain).
		Question(wire.NewQuestion(qname, qtype)).
		Authority(rec).
		Authority(wire.NewRecord(owner, time.Hour, sig)).
		Build()
}

// typesAt returns the RR types present at name.
func (z *signedZone) typesAt(name wire.Name) []rrtype.Type {
	seen := map[rrtype.Type]struct{}{}
	for k := range z.rrsets {
		if k.name == name.String() {
			seen[k.typ] = struct{}{}
		}
	}
	out := make([]rrtype.Type, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// nextOwnerAfter returns a synthetic next-owner name suitable for a NoData
// NSEC: prefixes a "\x00" label so the returned name sorts immediately
// after name in canonical order. Tests do not exercise inter-name
// ordering deeply.
func (z *signedZone) nextOwnerAfter(name wire.Name) wire.Name {
	labels := []string{"\x00"}
	for l := range name.Labels() {
		labels = append(labels, string(l))
	}
	n, err := wire.NameFromLabels(labels...)
	if err != nil {
		return name
	}
	return n
}

// coveringNSEC returns (owner, next) such that owner < qname < next in
// canonical order, drawn from the names actually present in the zone.
func (z *signedZone) coveringNSEC(qname wire.Name) (wire.Name, wire.Name) {
	// Collect existing owner names.
	names := map[string]wire.Name{}
	for k := range z.rrsets {
		if _, ok := names[k.name]; ok {
			continue
		}
		n, err := wire.ParseName(k.name)
		if err != nil {
			continue
		}
		names[k.name] = n
	}
	if len(names) == 0 {
		return z.apex, qname
	}
	sorted := make([]wire.Name, 0, len(names))
	for _, n := range names {
		sorted = append(sorted, n)
	}
	sort.Slice(sorted, func(i, j int) bool {
		return canonicalLess(sorted[i], sorted[j])
	})
	for i := range sorted {
		next := sorted[(i+1)%len(sorted)]
		if canonicalLess(sorted[i], qname) && canonicalLess(qname, next) {
			return sorted[i], next
		}
	}
	// Fallback wrap: use last → first.
	return sorted[len(sorted)-1], sorted[0]
}

func canonicalLess(a, b wire.Name) bool {
	return canonicalForm(a) < canonicalForm(b)
}

func canonicalForm(n wire.Name) string {
	var labels []string
	for l := range n.Labels() {
		labels = append(labels, string(l))
	}
	// Reverse for root-first ordering.
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	out := ""
	for _, l := range labels {
		out += l + "\x01" // label separator that sorts before any content byte
	}
	return out
}

// keyMat bundles a generated keypair with its DNSKEY rdata.
type keyMat struct {
	alg     rdata.DNSSECAlgorithm
	dnskey  rdata.DNSKEY
	ecdsa   *ecdsa.PrivateKey
	ed25519 ed25519.PrivateKey
}

func newKey(t *testing.T, alg rdata.DNSSECAlgorithm, ksk bool) keyMat {
	t.Helper()
	flags := uint16(rdata.DNSKEYFlagZone)
	if ksk {
		flags |= rdata.DNSKEYFlagSEP
	}
	switch alg {
	case rdata.AlgECDSAP256SHA256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		pub := append(priv.PublicKey.X.FillBytes(make([]byte, 32)),
			priv.PublicKey.Y.FillBytes(make([]byte, 32))...)
		return keyMat{
			alg:    alg,
			dnskey: rdata.NewDNSKEY(flags, 3, alg, pub),
			ecdsa:  priv,
		}
	case rdata.AlgECDSAP384SHA384:
		priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)
		pub := append(priv.PublicKey.X.FillBytes(make([]byte, 48)),
			priv.PublicKey.Y.FillBytes(make([]byte, 48))...)
		return keyMat{
			alg:    alg,
			dnskey: rdata.NewDNSKEY(flags, 3, alg, pub),
			ecdsa:  priv,
		}
	case rdata.AlgED25519:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		return keyMat{
			alg:     alg,
			dnskey:  rdata.NewDNSKEY(flags, 3, alg, pub),
			ed25519: priv,
		}
	default:
		t.Fatalf("unsupported alg %d", alg)
	}
	return keyMat{}
}

// signRRset returns the RRSIG for set using the zone's ZSK. DNSKEY rrsets
// are signed with the KSK.
func (z *signedZone) signRRset(set []wire.Record) rdata.RRSIG {
	if len(set) == 0 {
		return rdata.RRSIG{}
	}
	useKSK := set[0].Type() == rrtype.DNSKEY
	k := z.zsk
	if useKSK {
		k = z.ksk
	}
	exp := z.now.Add(z.dur)
	inc := z.now.Add(-z.dur)
	skeleton := rdata.NewRRSIG(set[0].Type(), k.alg,
		uint8(set[0].Name().NumLabels()), set[0].TTL(),
		exp, inc, dnssec.KeyTag(k.dnskey), z.apex, nil)
	payload, err := dnssec.SignedData(set, skeleton)
	if err != nil {
		panic(err)
	}
	var sigBytes []byte
	switch k.alg {
	case rdata.AlgECDSAP256SHA256:
		h := sha256.Sum256(payload)
		r, s, err := ecdsa.Sign(rand.Reader, k.ecdsa, h[:])
		if err != nil {
			panic(err)
		}
		sigBytes = make([]byte, 64)
		r.FillBytes(sigBytes[:32])
		s.FillBytes(sigBytes[32:])
	case rdata.AlgECDSAP384SHA384:
		h := sha512.Sum384(payload)
		r, s, err := ecdsa.Sign(rand.Reader, k.ecdsa, h[:])
		if err != nil {
			panic(err)
		}
		sigBytes = make([]byte, 96)
		r.FillBytes(sigBytes[:48])
		s.FillBytes(sigBytes[48:])
	case rdata.AlgED25519:
		sigBytes = ed25519.Sign(k.ed25519, payload)
	default:
		panic(fmt.Errorf("unsupported alg %d", k.alg))
	}
	return rdata.NewRRSIG(set[0].Type(), k.alg,
		uint8(set[0].Name().NumLabels()), set[0].TTL(),
		exp, inc, dnssec.KeyTag(k.dnskey), z.apex, sigBytes)
}

// publishDNSKEY ensures the DNSKEY rrset exists at the apex.
func (z *signedZone) publishDNSKEY() {
	for _, k := range z.dnskeys {
		z.addRR(wire.NewRecord(z.apex, time.Hour, k))
	}
}

// rootAnchor returns an Anchor matching z's KSK — used for tests that
// install z as the root of trust.
func (z *signedZone) rootAnchor(t *testing.T) (anchorWithDS, error) {
	t.Helper()
	digest, err := dnssec.DSDigest(z.apex, z.ksk.dnskey, rdata.DigestSHA256)
	if err != nil {
		return anchorWithDS{}, err
	}
	return anchorWithDS{
		apex: z.apex,
		ds: rdata.NewDS(dnssec.KeyTag(z.ksk.dnskey), z.ksk.dnskey.Algorithm(),
			rdata.DigestSHA256, digest),
	}, nil
}

type anchorWithDS struct {
	apex wire.Name
	ds   rdata.DS
}
