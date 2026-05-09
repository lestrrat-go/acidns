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

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/zonefile"
)

// ErrNoSOA is returned when a Zone is added that has no SOA record.
// An authoritative zone without an SOA cannot synthesise negative
// responses and is therefore rejected at AddZone time.
var ErrNoSOA = errors.New("authoritative: zone has no SOA")

// maxCNAMEChain bounds CNAME chasing within a single response so a malformed
// zone with a self-referential CNAME loop cannot stall a request.
const maxCNAMEChain = 8

// Authoritative is the public face of the authoritative server. It both
// implements acidns.Handler and exposes zone management methods.
type Authoritative interface {
	acidns.Handler
	AddZone(z zonefile.Zone) error
	Zones() []wire.Name
}

type authoritative struct {
	mu            sync.RWMutex
	zones         map[string]*zoneIndex
	notifyHandler NotifyHandler
	notifyPolicy  NotifyPolicy
	axfrPolicy    AXFRPolicy
	updatePolicy  UpdatePolicy
}

// zoneIndex is the per-zone lookup-friendly form of a Zone.
type zoneIndex struct {
	origin     wire.Name
	soaRec     wire.Record
	byName     map[string][]wire.Record // key = canonical wire of name
	namesExist map[string]struct{}      // names with records, plus empty non-terminals
}

// New returns a new Authoritative.
func New(opts ...Option) (Authoritative, error) {
	a := &authoritative{zones: make(map[string]*zoneIndex)}
	c := &config{}
	for _, o := range opts {
		o.applyAuth(c)
	}
	a.notifyHandler = c.notifyHandler
	a.notifyPolicy = c.notifyPolicy
	a.axfrPolicy = c.axfrPolicy
	a.updatePolicy = c.updatePolicy
	for _, z := range c.zones {
		if err := a.AddZone(z); err != nil {
			return nil, err
		}
	}
	return a, nil
}

func (a *authoritative) AddZone(z zonefile.Zone) error {
	soa, soaRec, ok := z.SOA()
	if !ok {
		return fmt.Errorf("%w: %s", ErrNoSOA, z.Origin())
	}
	_ = soa // SOA captured via record
	idx := &zoneIndex{
		origin:     z.Origin(),
		soaRec:     soaRec,
		byName:     make(map[string][]wire.Record),
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

func (a *authoritative) Zones() []wire.Name {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]wire.Name, 0, len(a.zones))
	for _, z := range a.zones {
		out = append(out, z.origin)
	}
	return out
}

// ServeDNS implements acidns.Handler.
func (a *authoritative) ServeDNS(ctx context.Context, w acidns.ResponseWriter, q wire.Message) {
	if q.Flags().Opcode() == wire.OpcodeUpdate {
		a.serveUpdate(ctx, w, q)
		return
	}
	if q.Flags().Opcode() == wire.OpcodeNotify {
		a.serveNotify(ctx, w, q)
		return
	}
	if len(q.Questions()) == 1 {
		switch q.Questions()[0].Type() {
		case rrtype.AXFR:
			a.serveAXFR(ctx, w, q)
			return
		case rrtype.IXFR:
			// RFC 1995 §3: a server lacking a journal MAY answer IXFR
			// with an AXFR-format response.
			a.serveAXFR(ctx, w, q)
			return
		}
	}
	resp := a.answer(q)
	_ = w.WriteMsg(resp)
}

// AXFRChunkBudget is the soft cap on per-message body size used by
// the AXFR streamer. Conservatively below the 65535 framing limit
// and below most middleboxes' single-frame thresholds; tuned to keep
// packets small enough that a slow link delivers progress between
// idle timeouts. Exported so third-party authoritative
// implementations using [StreamAXFR] can reason about the same
// chunking the built-in handler does.
const AXFRChunkBudget = 16 * 1024

// axfrChunkBudget retains the lower-case spelling for internal use.
const axfrChunkBudget = AXFRChunkBudget

// StreamAXFR writes an RFC 5936 AXFR response stream for the given
// zone to w. It is the framing-and-chunking primitive behind the
// built-in authoritative server's AXFR path, exported so a custom
// authoritative implementation can serve transfers with the same
// behaviour.
//
// q is the AXFR request whose ID, RD bit, and question are echoed
// into every emitted message. soa is the apex SOA — emitted as the
// first and last answer per RFC 5936 §2.2. body is the rest of the
// zone in the order the receiver should see it; any SOA records in
// body are ignored (the apex SOA is added at the boundaries by
// StreamAXFR itself).
//
// w must be a TCP-style ResponseWriter whose WriteMsg may be called
// multiple times — AXFR is multi-message by design. UDP transports
// will fail on the second WriteMsg; gate accordingly before calling.
//
// StreamAXFR does NOT enforce policy — caller-side authentication
// (TSIG, ACL) and authority-of-origin checks are the responsibility
// of the surrounding handler.
func StreamAXFR(w acidns.ResponseWriter, q wire.Message, soa wire.Record, body []wire.Record) error {
	if len(q.Questions()) == 0 {
		return fmt.Errorf("authoritative: StreamAXFR: request has no question")
	}
	question := q.Questions()[0]
	header := func() *wire.Builder {
		return wire.NewBuilder().
			ID(q.ID()).
			Response(true).
			RecursionDesired(q.Flags().RecursionDesired()).
			Question(question)
	}

	b := header().Authoritative(true).Answer(soa)
	soaSize := estimateRecordSize(soa)
	used := soaSize

	flush := func() error {
		if err := w.WriteMsg(mustBuild(b, q)); err != nil {
			return err
		}
		b = header().Authoritative(true)
		used = 0
		return nil
	}

	for _, rec := range body {
		if rec.Type() == rrtype.SOA {
			continue
		}
		recSize := estimateRecordSize(rec)
		if used > 0 && used+recSize+soaSize > axfrChunkBudget {
			if err := flush(); err != nil {
				return err
			}
		}
		b = b.Answer(rec)
		used += recSize
	}
	if used+soaSize > axfrChunkBudget {
		if err := flush(); err != nil {
			return err
		}
	}
	b = b.Answer(soa)
	return w.WriteMsg(mustBuild(b, q))
}

// serveAXFR implements RFC 5936 AXFR. The zone is streamed across one or
// more DNS messages on the same TCP connection: the first message starts
// with the apex SOA, subsequent messages carry continuation records, and
// the final message ends with the apex SOA. Each message is a complete,
// self-framed DNS response with AA=1; per RFC 5936 §2.2 a receiver
// reassembles the zone by concatenating answer sections in arrival order.
func (a *authoritative) serveAXFR(ctx context.Context, w acidns.ResponseWriter, q wire.Message) {
	question := q.Questions()[0]
	header := func() *wire.Builder {
		return wire.NewBuilder().
			ID(q.ID()).
			Response(true).
			RecursionDesired(q.Flags().RecursionDesired()).
			Question(question)
	}

	// AXFR over UDP is not allowed.
	if w.Network() != "tcp" {
		_ = w.WriteMsg(mustBuild(setRCODE(header(), q, wire.RCODERefused), q))
		return
	}

	zone := a.findZone(question.Name())
	if zone == nil {
		_ = w.WriteMsg(mustBuild(setRCODE(header(), q, wire.RCODERefused), q))
		return
	}
	if !zone.origin.Equal(question.Name()) {
		// AXFR target must equal a zone's apex.
		_ = w.WriteMsg(mustBuild(setRCODE(header(), q, wire.RCODENotAuth), q))
		return
	}

	// Default-deny when no policy is installed: zone contents leave
	// the server only when the operator has explicitly authorised it.
	policy := a.axfrPolicy
	if policy == nil || !policy(ctx, w, q) {
		_ = w.WriteMsg(mustBuild(setRCODE(header(), q, wire.RCODERefused), q))
		return
	}

	_ = StreamAXFR(w, q, zone.soaRec, zone.allRecordsOrdered())
}

// estimateRecordSize returns an upper-bound on the wire size of rec
// before name compression. Real on-the-wire size is ≤ this estimate,
// which keeps the AXFR chunker comfortably under axfrChunkBudget.
func estimateRecordSize(rec wire.Record) int {
	const fixedHeader = 10 // type(2) + class(2) + ttl(4) + rdlen(2)
	return rec.Name().WireLen() + fixedHeader + len(rdata.Pack(rec.RData()))
}

func (a *authoritative) answer(q wire.Message) wire.Message {
	b := wire.NewBuilder().
		ID(q.ID()).
		Response(true).
		RecursionDesired(q.Flags().RecursionDesired())

	if len(q.Questions()) == 0 {
		return mustBuild(setRCODE(b, q, wire.RCODEFormErr), q)
	}
	question := q.Questions()[0]
	b = b.Question(question)

	zone := a.findZone(question.Name())
	if zone == nil {
		return mustBuild(setRCODE(b, q, wire.RCODERefused), q)
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
	return mustBuild(setRCODE(b, q, res.rcode), q)
}

// setRCODE writes the response RCODE to b, attaching an OPT echo when
// the request carried EDNS (RFC 6891 §6.1.1) and splitting the 12-bit
// RCODE into the header's low 4 bits and the OPT's 8-bit extended RCODE
// (RFC 6891 §6.1.3). For RCODE values that fit in 4 bits the OPT's
// extended-RCODE field is zero, matching the no-EDNS encoding.
func setRCODE(b *wire.Builder, q wire.Message, code wire.RCODE) *wire.Builder {
	b = b.RCODE(wire.RCODE(uint8(code) & 0x0f))
	qe, ok := q.EDNS()
	if !ok || qe == nil {
		return b
	}
	eb := wire.NewEDNSBuilder().
		UDPSize(1232). // DNS Flag Day 2020 default
		DO(qe.DO())
	if hi := uint8(code) >> 4; hi != 0 {
		eb = eb.ExtendedRCODE(hi)
	}
	ed, err := eb.Build()
	if err != nil {
		return b
	}
	return b.EDNS(ed)
}

// echoEDNS attaches an OPT pseudo-RR to the response builder if the
// request carried one. Used by code paths that don't carry an explicit
// RCODE (e.g. successful AXFR envelopes); for paths that set a RCODE
// use [setRCODE] instead so the extended bits are not silently dropped.
func echoEDNS(b *wire.Builder, q wire.Message) *wire.Builder {
	return setRCODE(b, q, wire.RCODENoError)
}

// mustBuild builds m. On builder error it returns a SERVFAIL that still
// echoes the original ID and (if present) question — RFC 1035 §4.1.1
// requires the question section to be copied from the request, and an
// unsolicited response with no question is dropped by clients that index
// outstanding queries by ID+question.
func mustBuild(b *wire.Builder, q wire.Message) wire.Message {
	m, err := b.Build()
	if err == nil {
		return m
	}
	fb := wire.NewBuilder().
		ID(q.ID()).
		Response(true).
		RecursionDesired(q.Flags().RecursionDesired())
	if qs := q.Questions(); len(qs) > 0 {
		fb = fb.Question(qs[0])
	}
	// Echo OPT so EDNS-aware clients still see EDNS support on the
	// fallback path; otherwise an OPT-bearing query that hits this
	// branch looks like the server lost EDNS support and the client
	// downgrades on subsequent queries.
	fb = setRCODE(fb, q, wire.RCODEServFail)
	if out, err := fb.Build(); err == nil {
		return out
	}
	// Last resort — must not hang the caller; this should never trigger.
	out, _ := wire.NewBuilder().Response(true).RCODE(wire.RCODEServFail).Build()
	return out
}

// findZone returns the deepest zone whose origin is an ancestor of name.
func (a *authoritative) findZone(name wire.Name) *zoneIndex {
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
	answer     []wire.Record
	authority  []wire.Record
	additional []wire.Record
	rcode      wire.RCODE
	aa         bool // false for downward referrals
}

// lookup applies the simplified RFC 1034 §4.3.2 algorithm (with RFC 4592
// wildcard synthesis and downward delegation detection) for a single QNAME
// and QTYPE within this zone.
func (z *zoneIndex) lookup(qname wire.Name, qtype rrtype.Type) lookupResult {
	if dp, nsRecs := z.findDelegation(qname); len(nsRecs) > 0 {
		_ = dp
		return lookupResult{
			authority:  nsRecs,
			additional: z.collectGlue(nsRecs),
			rcode:      wire.RCODENoError,
			aa:         false,
		}
	}
	res := lookupResult{aa: true}
	res.answer, res.authority, res.rcode = z.lookupAuthoritative(qname, qtype)
	return res
}

func (z *zoneIndex) lookupAuthoritative(qname wire.Name, qtype rrtype.Type) (answer, authority []wire.Record, rcode wire.RCODE) {
	current := qname
	for chain := range maxCNAMEChain {
		recs, hasRecs := z.byName[nameKey(current)]
		if hasRecs {
			ans, follow, done := z.matchRRSet(recs, qtype)
			if done {
				if len(ans) > 0 {
					answer = append(answer, ans...)
					return answer, nil, wire.RCODENoError
				}
				// NODATA at this name.
				if chain == 0 {
					return nil, []wire.Record{z.soaRec}, wire.RCODENoError
				}
				return answer, nil, wire.RCODENoError
			}
			// CNAME chase
			answer = append(answer, ans...)
			current = follow
			continue
		}

		if _, exists := z.namesExist[nameKey(current)]; exists {
			// Empty non-terminal — NODATA per RFC 8020.
			if chain == 0 {
				return nil, []wire.Record{z.soaRec}, wire.RCODENoError
			}
			return answer, nil, wire.RCODENoError
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
						return answer, nil, wire.RCODENoError
					}
					if chain == 0 {
						return nil, []wire.Record{z.soaRec}, wire.RCODENoError
					}
					return answer, nil, wire.RCODENoError
				}
				answer = append(answer, ans...)
				current = follow
				continue
			}
		}

		// No exact, no empty non-terminal, no wildcard → NXDOMAIN.
		if chain == 0 {
			return nil, []wire.Record{z.soaRec}, wire.RCODENXDomain
		}
		return answer, nil, wire.RCODENoError
	}
	return answer, nil, wire.RCODEServFail
}

// matchRRSet returns:
//   - ans: the records from recs that satisfy qtype (or the CNAME hop);
//   - follow: a CNAME target if a chase should continue, else zero value;
//   - done: true when the lookup is complete (whether successfully or NODATA).
func (z *zoneIndex) matchRRSet(recs []wire.Record, qtype rrtype.Type) (ans []wire.Record, follow wire.Name, done bool) {
	var matched []wire.Record
	for _, r := range recs {
		if r.Type() == qtype {
			matched = append(matched, r)
		}
	}
	if len(matched) > 0 {
		return matched, wire.Name{}, true
	}
	if qtype != rrtype.CNAME {
		for _, r := range recs {
			if c, ok := wire.RDataAs[rdata.CNAME](r); ok {
				return []wire.Record{r}, c.Target(), false
			}
		}
	}
	return nil, wire.Name{}, true
}

// closestEncloser walks up from name (exclusive) and returns the deepest
// existing ancestor in the zone.
func (z *zoneIndex) closestEncloser(name wire.Name) (wire.Name, bool) {
	cur, ok := name.Parent()
	if !ok {
		return wire.Name{}, false
	}
	for {
		if _, ok := z.namesExist[nameKey(cur)]; ok {
			return cur, true
		}
		next, ok := cur.Parent()
		if !ok {
			return wire.Name{}, false
		}
		cur = next
	}
}

func wildcardKey(encloser wire.Name) string {
	if encloser.IsRoot() {
		// "*."
		n, _ := wire.NameFromLabels("*")
		return nameKey(n)
	}
	// Build *.encloser by walking encloser's labels.
	var labels []string
	labels = append(labels, "*")
	for l := range encloser.Labels() {
		labels = append(labels, string(l))
	}
	n, err := wire.NameFromLabels(labels...)
	if err != nil {
		return ""
	}
	return nameKey(n)
}

func rewriteOwners(recs []wire.Record, owner wire.Name) []wire.Record {
	if len(recs) == 0 {
		return recs
	}
	out := make([]wire.Record, len(recs))
	for i, r := range recs {
		out[i] = wire.NewRecordClass(owner, r.Class(), r.TTL(), r.RData())
	}
	return out
}

// findDelegation walks from qname up toward the zone apex, returning the
// deepest ancestor (excluding the zone origin) that has NS records — the
// delegation point. Returns the empty name and nil if QNAME does not
// cross a delegation.
func (z *zoneIndex) findDelegation(qname wire.Name) (wire.Name, []wire.Record) {
	cur := qname
	for {
		if cur.Equal(z.origin) {
			return wire.Name{}, nil
		}
		if recs, ok := z.byName[nameKey(cur)]; ok {
			var ns []wire.Record
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
			return wire.Name{}, nil
		}
		cur = parent
	}
}

// collectGlue returns A/AAAA records owned by NS targets that the zone
// itself contains. Out-of-bailiwick targets are silently skipped — the
// recursing resolver is expected to look those up directly.
func (z *zoneIndex) collectGlue(nsRecs []wire.Record) []wire.Record {
	var glue []wire.Record
	for _, ns := range nsRecs {
		nsRD, ok := wire.RDataAs[rdata.NS](ns)
		if !ok {
			continue
		}
		recs, ok := z.byName[nameKey(nsRD.NSDName())]
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
func nameKey(n wire.Name) string {
	return string(n.AppendWire(nil))
}

// allRecordsOrdered returns every record in the zone. Order is unspecified
// (Go map iteration); callers needing deterministic output sort externally.
func (z *zoneIndex) allRecordsOrdered() []wire.Record {
	var out []wire.Record
	for _, rs := range z.byName {
		out = append(out, rs...)
	}
	return out
}
