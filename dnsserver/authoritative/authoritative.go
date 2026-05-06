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
	origin dnsname.Name
	soaRec dnsmsg.Record
	byName map[string][]dnsmsg.Record // key = canonical wire of name
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
		origin: z.Origin(),
		soaRec: soaRec,
		byName: make(map[string][]dnsmsg.Record),
	}
	for _, rec := range z.Records() {
		k := nameKey(rec.Name())
		idx.byName[k] = append(idx.byName[k], rec)
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
	resp := a.answer(q)
	_ = w.WriteMsg(resp)
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
	b = b.Authoritative(true)

	answers, authority, rcode := zone.lookup(question.Name(), question.Type())
	for _, r := range answers {
		b = b.Answer(r)
	}
	for _, r := range authority {
		b = b.Authority(r)
	}
	if rcode != dnsmsg.RCODENoError {
		b = b.RCODE(rcode)
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

// lookup applies the simplified RFC 1034 §4.3.2 algorithm for a single QNAME
// and QTYPE within this zone, returning the answer records, the authority
// records (SOA on negative responses), and the RCODE.
func (z *zoneIndex) lookup(qname dnsname.Name, qtype rrtype.Type) (answer, authority []dnsmsg.Record, rcode dnsmsg.RCODE) {
	current := qname
	for chain := 0; chain < maxCNAMEChain; chain++ {
		recs, exists := z.byName[nameKey(current)]
		if !exists {
			if chain == 0 {
				return nil, []dnsmsg.Record{z.soaRec}, dnsmsg.RCODENXDomain
			}
			// CNAME pointed to a name not in zone — return what we have.
			return answer, nil, dnsmsg.RCODENoError
		}
		// Match QTYPE first.
		var matched []dnsmsg.Record
		for _, r := range recs {
			if r.Type() == qtype {
				matched = append(matched, r)
			}
		}
		if len(matched) > 0 {
			answer = append(answer, matched...)
			return answer, nil, dnsmsg.RCODENoError
		}
		// No exact match; if there's a CNAME, follow it.
		if qtype != rrtype.CNAME {
			var cname rdata.CNAME
			var cnameRR dnsmsg.Record
			for _, r := range recs {
				if r.Type() == rrtype.CNAME {
					cname = r.RData().(rdata.CNAME)
					cnameRR = r
					break
				}
			}
			if cname != nil {
				answer = append(answer, cnameRR)
				current = cname.Target()
				continue
			}
		}
		// Name exists but no answers of the requested type → NODATA.
		if chain == 0 {
			return nil, []dnsmsg.Record{z.soaRec}, dnsmsg.RCODENoError
		}
		return answer, nil, dnsmsg.RCODENoError
	}
	// CNAME chain exceeded.
	return answer, nil, dnsmsg.RCODEServFail
}

// nameKey returns a comparable canonical key for a name. It uses the wire
// representation already canonicalised by dnsname (lowercase, terminator
// included), wrapped in a string for use as a map key.
func nameKey(n dnsname.Name) string {
	return string(n.AppendWire(nil))
}
