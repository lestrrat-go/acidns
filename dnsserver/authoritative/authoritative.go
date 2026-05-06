// Package authoritative implements an authoritative DNS Handler that
// answers queries from one or more loaded Zones.
//
// It is deliberately minimal — exact-match lookups, CNAME chasing within
// the zone, and the standard RFC 1034 §4.3.2 negative-answer disposition
// (NODATA with SOA in authority for type misses, NXDOMAIN with SOA for
// name misses, REFUSED for out-of-bailiwick QNAMEs). Wildcards, DNSSEC
// signing, and zone delegations are out of scope for this version.
package authoritative

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/lestrrat-go/acidns/dnsserver"
	"github.com/lestrrat-go/acidns/dnszone"
)

// ErrNoSOA is returned when a Zone is added that has no SOA record.
// An authoritative zone without an SOA cannot synthesise negative
// responses and is therefore rejected at AddZone time.
var ErrNoSOA = errors.New("authoritative: zone has no SOA")

// maxCNAMEChain bounds CNAME chasing within a single response so a malformed
// zone with a self-referential CNAME loop cannot stall a request.
const maxCNAMEChain = 8

// Authoritative is the public face of the authoritative server. It both
// implements dnsserver.Handler and exposes zone management methods.
type Authoritative interface {
	dnsserver.Handler
	AddZone(z dnszone.Zone) error
	Zones() []dnsname.Name
}

// Option configures an Authoritative at construction.
type Option interface{ applyAuth(*config) }

type optionFunc func(*config)

func (f optionFunc) applyAuth(c *config) { f(c) }

type config struct {
	zones []dnszone.Zone
}

// WithZone adds z to the server's zones.
func WithZone(z dnszone.Zone) Option {
	return optionFunc(func(c *config) { c.zones = append(c.zones, z) })
}

type authoritative struct {
	mu    sync.RWMutex
	zones map[string]*zoneIndex
}

// zoneIndex is the per-zone lookup-friendly form of a Zone.
type zoneIndex struct {
	origin     dnsname.Name
	soaRec     dnsmsg.Record
	byName     map[string][]dnsmsg.Record // key = canonical wire of name
	namesExist map[string]struct{}        // names with records, plus empty non-terminals
}

// New returns a new Authoritative.
func New(opts ...Option) (Authoritative, error) {
	a := &authoritative{zones: make(map[string]*zoneIndex)}
	c := &config{}
	for _, o := range opts {
		o.applyAuth(c)
	}
	for _, z := range c.zones {
		if err := a.AddZone(z); err != nil {
			return nil, err
		}
	}
	return a, nil
}

func (a *authoritative) AddZone(z dnszone.Zone) error {
	soa, soaRec, ok := z.SOA()
	if !ok {
		return fmt.Errorf("%w: %s", ErrNoSOA, z.Origin())
	}
	_ = soa // SOA captured via record
	idx := &zoneIndex{
		origin:     z.Origin(),
		soaRec:     soaRec,
		byName:     make(map[string][]dnsmsg.Record),
		namesExist: make(map[string]struct{}),
	}
	for _, rec := range z.Records() {
		k := nameKey(rec.Name())
		idx.byName[k] = append(idx.byName[k], rec)
		// Mark the name and every ancestor up to (and including) the zone
		// origin as existing — empty non-terminals must register so that
		// wildcard synthesis stops at the closest encloser.
		cur := rec.Name()
		for {
			idx.namesExist[nameKey(cur)] = struct{}{}
			if cur.Equal(idx.origin) {
				break
			}
			parent, ok := cur.Parent()
			if !ok {
				break
			}
			cur = parent
		}
	}
	a.mu.Lock()
	a.zones[nameKey(z.Origin())] = idx
	a.mu.Unlock()
	return nil
}

func (a *authoritative) Zones() []dnsname.Name {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]dnsname.Name, 0, len(a.zones))
	for _, z := range a.zones {
		out = append(out, z.origin)
	}
	return out
}

// ServeDNS implements dnsserver.Handler.
func (a *authoritative) ServeDNS(ctx context.Context, w dnsserver.ResponseWriter, q dnsmsg.Message) {
	if q.Flags().Opcode() == dnsmsg.OpcodeUpdate {
		a.serveUpdate(w, q)
		return
	}
	if len(q.Questions()) == 1 {
		switch q.Questions()[0].Type() {
		case rrtype.AXFR:
			a.serveAXFR(w, q)
			return
		case rrtype.IXFR:
			// RFC 1995 §3: a server lacking a journal MAY answer IXFR
			// with an AXFR-format response.
			a.serveAXFR(w, q)
			return
		}
	}
	resp := a.answer(q)
	_ = w.WriteMsg(resp)
}

// serveAXFR implements RFC 5936 single-message AXFR. The full zone fits in
// one DNS message for our intended scale; multi-message streaming can be
// added later by emitting multiple WriteMsg calls.
func (a *authoritative) serveAXFR(w dnsserver.ResponseWriter, q dnsmsg.Message) {
	question := q.Questions()[0]
	b := dnsmsg.NewBuilder().
		ID(q.ID()).
		Response(true).
		RecursionDesired(q.Flags().RecursionDesired()).
		Question(question)

	// AXFR over UDP is not allowed.
	if w.Network() != "tcp" {
		_ = w.WriteMsg(mustBuild(b.RCODE(dnsmsg.RCODERefused)))
		return
	}

	zone := a.findZone(question.Name())
	if zone == nil {
		_ = w.WriteMsg(mustBuild(b.RCODE(dnsmsg.RCODERefused)))
		return
	}
	if !zone.origin.Equal(question.Name()) {
		// AXFR target must equal a zone's apex.
		_ = w.WriteMsg(mustBuild(b.RCODE(dnsmsg.RCODENotAuth)))
		return
	}

	b = b.Authoritative(true).Answer(zone.soaRec)
	for _, rec := range zone.allRecordsOrdered() {
		if rec.Type() == rrtype.SOA {
			continue // skip the apex SOA (added at the boundaries)
		}
		b = b.Answer(rec)
	}
	b = b.Answer(zone.soaRec)
	_ = w.WriteMsg(mustBuild(b))
}

func (a *authoritative) answer(q dnsmsg.Message) dnsmsg.Message {
	b := dnsmsg.NewBuilder().
		ID(q.ID()).
		Response(true).
		RecursionDesired(q.Flags().RecursionDesired())

	if len(q.Questions()) == 0 {
		return mustBuild(b.RCODE(dnsmsg.RCODEFormErr))
	}
	question := q.Questions()[0]
	b = b.Question(question)

	zone := a.findZone(question.Name())
	if zone == nil {
		return mustBuild(b.RCODE(dnsmsg.RCODERefused))
	}

	res := zone.lookup(question.Name(), question.Type())
	b = b.Authoritative(res.aa)
	for _, r := range res.answer {
		b = b.Answer(r)
	}
	for _, r := range res.authority {
		b = b.Authority(r)
	}
	for _, r := range res.additional {
		b = b.Additional(r)
	}
	if res.rcode != dnsmsg.RCODENoError {
		b = b.RCODE(res.rcode)
	}
	return mustBuild(b)
}

func mustBuild(b dnsmsg.Builder) dnsmsg.Message {
	m, err := b.Build()
	if err != nil {
		// Builder errors at this level are programmer errors — a malformed
		// authoritative response is preferable to a hang.
		fb, _ := dnsmsg.NewBuilder().Response(true).RCODE(dnsmsg.RCODEServFail).Build()
		return fb
	}
	return m
}

// findZone returns the deepest zone whose origin is an ancestor of name.
func (a *authoritative) findZone(name dnsname.Name) *zoneIndex {
	a.mu.RLock()
	defer a.mu.RUnlock()
	cur := name
	for {
		if z, ok := a.zones[nameKey(cur)]; ok {
			return z
		}
		parent, ok := cur.Parent()
		if !ok {
			return nil
		}
		cur = parent
	}
}

// lookupResult captures everything needed to populate a response section.
type lookupResult struct {
	answer     []dnsmsg.Record
	authority  []dnsmsg.Record
	additional []dnsmsg.Record
	rcode      dnsmsg.RCODE
	aa         bool // false for downward referrals
}

// lookup applies the simplified RFC 1034 §4.3.2 algorithm (with RFC 4592
// wildcard synthesis and downward delegation detection) for a single QNAME
// and QTYPE within this zone.
func (z *zoneIndex) lookup(qname dnsname.Name, qtype rrtype.Type) lookupResult {
	if dp, nsRecs := z.findDelegation(qname); len(nsRecs) > 0 {
		_ = dp
		return lookupResult{
			authority:  nsRecs,
			additional: z.collectGlue(nsRecs),
			rcode:      dnsmsg.RCODENoError,
			aa:         false,
		}
	}
	res := lookupResult{aa: true}
	res.answer, res.authority, res.rcode = z.lookupAuthoritative(qname, qtype)
	return res
}

func (z *zoneIndex) lookupAuthoritative(qname dnsname.Name, qtype rrtype.Type) (answer, authority []dnsmsg.Record, rcode dnsmsg.RCODE) {
	current := qname
	for chain := 0; chain < maxCNAMEChain; chain++ {
		recs, hasRecs := z.byName[nameKey(current)]
		if hasRecs {
			ans, follow, done := z.matchRRSet(recs, qtype)
			if done {
				if len(ans) > 0 {
					answer = append(answer, ans...)
					return answer, nil, dnsmsg.RCODENoError
				}
				// NODATA at this name.
				if chain == 0 {
					return nil, []dnsmsg.Record{z.soaRec}, dnsmsg.RCODENoError
				}
				return answer, nil, dnsmsg.RCODENoError
			}
			// CNAME chase
			answer = append(answer, ans...)
			current = follow
			continue
		}

		if _, exists := z.namesExist[nameKey(current)]; exists {
			// Empty non-terminal — NODATA per RFC 8020.
			if chain == 0 {
				return nil, []dnsmsg.Record{z.soaRec}, dnsmsg.RCODENoError
			}
			return answer, nil, dnsmsg.RCODENoError
		}

		// Try wildcard synthesis (RFC 4592).
		if encloser, ok := z.closestEncloser(current); ok {
			if wcRecs, found := z.byName[wildcardKey(encloser)]; found {
				ans, follow, done := z.matchRRSet(wcRecs, qtype)
				// Owner of synthesised RR = QNAME, not *.encloser.
				ans = rewriteOwners(ans, current)
				if done {
					if len(ans) > 0 {
						answer = append(answer, ans...)
						return answer, nil, dnsmsg.RCODENoError
					}
					if chain == 0 {
						return nil, []dnsmsg.Record{z.soaRec}, dnsmsg.RCODENoError
					}
					return answer, nil, dnsmsg.RCODENoError
				}
				answer = append(answer, ans...)
				current = follow
				continue
			}
		}

		// No exact, no empty non-terminal, no wildcard → NXDOMAIN.
		if chain == 0 {
			return nil, []dnsmsg.Record{z.soaRec}, dnsmsg.RCODENXDomain
		}
		return answer, nil, dnsmsg.RCODENoError
	}
	return answer, nil, dnsmsg.RCODEServFail
}

// matchRRSet returns:
//   - ans: the records from recs that satisfy qtype (or the CNAME hop);
//   - follow: a CNAME target if a chase should continue, else zero value;
//   - done: true when the lookup is complete (whether successfully or NODATA).
func (z *zoneIndex) matchRRSet(recs []dnsmsg.Record, qtype rrtype.Type) (ans []dnsmsg.Record, follow dnsname.Name, done bool) {
	var matched []dnsmsg.Record
	for _, r := range recs {
		if r.Type() == qtype {
			matched = append(matched, r)
		}
	}
	if len(matched) > 0 {
		return matched, dnsname.Name{}, true
	}
	if qtype != rrtype.CNAME {
		for _, r := range recs {
			if r.Type() == rrtype.CNAME {
				return []dnsmsg.Record{r}, r.RData().(rdata.CNAME).Target(), false
			}
		}
	}
	return nil, dnsname.Name{}, true
}

// closestEncloser walks up from name (exclusive) and returns the deepest
// existing ancestor in the zone.
func (z *zoneIndex) closestEncloser(name dnsname.Name) (dnsname.Name, bool) {
	cur, ok := name.Parent()
	if !ok {
		return dnsname.Name{}, false
	}
	for {
		if _, ok := z.namesExist[nameKey(cur)]; ok {
			return cur, true
		}
		next, ok := cur.Parent()
		if !ok {
			return dnsname.Name{}, false
		}
		cur = next
	}
}

func wildcardKey(encloser dnsname.Name) string {
	if encloser.IsRoot() {
		// "*."
		n, _ := dnsname.FromLabels("*")
		return nameKey(n)
	}
	// Build *.encloser by walking encloser's labels.
	var labels []string
	labels = append(labels, "*")
	for l := range encloser.Labels() {
		labels = append(labels, string(l))
	}
	n, err := dnsname.FromLabels(labels...)
	if err != nil {
		return ""
	}
	return nameKey(n)
}

func rewriteOwners(recs []dnsmsg.Record, owner dnsname.Name) []dnsmsg.Record {
	if len(recs) == 0 {
		return recs
	}
	out := make([]dnsmsg.Record, len(recs))
	for i, r := range recs {
		out[i] = dnsmsg.NewRecordClass(owner, r.Class(), r.TTL(), r.RData())
	}
	return out
}

// findDelegation walks from qname up toward the zone apex, returning the
// deepest ancestor (excluding the zone origin) that has NS records — the
// delegation point. Returns the empty name and nil if QNAME does not
// cross a delegation.
func (z *zoneIndex) findDelegation(qname dnsname.Name) (dnsname.Name, []dnsmsg.Record) {
	cur := qname
	for {
		if cur.Equal(z.origin) {
			return dnsname.Name{}, nil
		}
		if recs, ok := z.byName[nameKey(cur)]; ok {
			var ns []dnsmsg.Record
			for _, r := range recs {
				if r.Type() == rrtype.NS {
					ns = append(ns, r)
				}
			}
			if len(ns) > 0 {
				return cur, ns
			}
		}
		parent, ok := cur.Parent()
		if !ok {
			return dnsname.Name{}, nil
		}
		cur = parent
	}
}

// collectGlue returns A/AAAA records owned by NS targets that the zone
// itself contains. Out-of-bailiwick targets are silently skipped — the
// recursing resolver is expected to look those up directly.
func (z *zoneIndex) collectGlue(nsRecs []dnsmsg.Record) []dnsmsg.Record {
	var glue []dnsmsg.Record
	for _, ns := range nsRecs {
		target := ns.RData().(rdata.NS).NSDName()
		recs, ok := z.byName[nameKey(target)]
		if !ok {
			continue
		}
		for _, r := range recs {
			if r.Type() == rrtype.A || r.Type() == rrtype.AAAA {
				glue = append(glue, r)
			}
		}
	}
	return glue
}

// nameKey returns a comparable canonical key for a name. It uses the wire
// representation already canonicalised by dnsname (lowercase, terminator
// included), wrapped in a string for use as a map key.
func nameKey(n dnsname.Name) string {
	return string(n.AppendWire(nil))
}

// allRecordsOrdered returns every record in the zone. Order is unspecified
// (Go map iteration); callers needing deterministic output sort externally.
func (z *zoneIndex) allRecordsOrdered() []dnsmsg.Record {
	var out []dnsmsg.Record
	for _, rs := range z.byName {
		out = append(out, rs...)
	}
	return out
}
