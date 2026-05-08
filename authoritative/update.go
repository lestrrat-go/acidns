package authoritative

import (
	"bytes"
	"context"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// serveUpdate implements RFC 2136 dynamic update for an authoritative
// zone. UPDATE is gated by the [UpdatePolicy] installed via
// [WithUpdatePolicy]; with no policy installed (the default), every
// UPDATE is refused with REFUSED. Production deployments are expected
// to install a policy that performs TSIG (RFC 3007) or SIG(0)
// verification before admitting an update.
func (a *authoritative) serveUpdate(ctx context.Context, w acidns.ResponseWriter, q wire.Message) {
	b := wire.NewBuilder().
		ID(q.ID()).
		Response(true).
		Opcode(wire.OpcodeUpdate)
	for _, qq := range q.Questions() {
		b = b.Question(qq)
	}

	// Structural validity is checked first — a malformed UPDATE wire
	// gets FormErr regardless of policy, since rejecting it doesn't
	// reveal anything that the malformed-by-construction caller doesn't
	// already know.
	if len(q.Questions()) != 1 {
		_ = w.WriteMsg(mustBuild(setRCODE(b, q, wire.RCODEFormErr), q))
		return
	}
	zoneQ := q.Questions()[0]
	if zoneQ.Type() != rrtype.SOA {
		_ = w.WriteMsg(mustBuild(setRCODE(b, q, wire.RCODEFormErr), q))
		return
	}

	// Authorisation gate. With no policy installed, every UPDATE is
	// refused — we won't accept unauthenticated mutation by default.
	if a.updatePolicy == nil || !a.updatePolicy(ctx, w, q) {
		_ = w.WriteMsg(mustBuild(setRCODE(b, q, wire.RCODERefused), q))
		return
	}

	a.mu.Lock()
	zone, ok := a.zones[nameKey(zoneQ.Name())]
	if !ok {
		a.mu.Unlock()
		_ = w.WriteMsg(mustBuild(setRCODE(b, q, wire.RCODENotAuth), q))
		return
	}

	// Prerequisites — RFC 2136 §3.2. Run against the existing snapshot;
	// a prereq failure must not leave a partially-mutated zone behind.
	for _, p := range q.Answers() {
		if rcode := zone.checkPrereq(p); rcode != wire.RCODENoError {
			a.mu.Unlock()
			_ = w.WriteMsg(mustBuild(setRCODE(b, q, rcode), q))
			return
		}
	}

	// Update — RFC 2136 §3.4. Copy-on-write: mutate a clone and swap the
	// pointer atomically under the write lock. Readers that snapshotted
	// the previous *zoneIndex via findZone continue against an immutable
	// view, so a query in flight cannot race with the in-place map writes
	// applyUpdate would otherwise perform.
	newZone := zone.clone()
	for _, u := range q.Authorities() {
		newZone.applyUpdate(u)
	}
	a.zones[nameKey(zoneQ.Name())] = newZone
	a.mu.Unlock()
	_ = w.WriteMsg(mustBuild(echoEDNS(b, q), q))
}

// clone returns a deep copy of z suitable for in-place mutation. Once a
// *zoneIndex has been published via a.zones, its maps are treated as
// immutable; any modification produces a fresh clone that replaces the
// published pointer atomically under a.mu.
func (z *zoneIndex) clone() *zoneIndex {
	out := &zoneIndex{
		origin:     z.origin,
		soaRec:     z.soaRec,
		byName:     make(map[string][]wire.Record, len(z.byName)),
		namesExist: make(map[string]struct{}, len(z.namesExist)),
	}
	for k, recs := range z.byName {
		cp := make([]wire.Record, len(recs))
		copy(cp, recs)
		out.byName[k] = cp
	}
	for k := range z.namesExist {
		out.namesExist[k] = struct{}{}
	}
	return out
}

func (z *zoneIndex) checkPrereq(p wire.Record) wire.RCODE {
	name := p.Name()
	t := p.Type()
	class := p.Class()

	hasName := func() bool {
		_, ok := z.byName[nameKey(name)]
		return ok
	}
	hasType := func() bool {
		recs, ok := z.byName[nameKey(name)]
		if !ok {
			return false
		}
		for _, r := range recs {
			if r.Type() == t {
				return true
			}
		}
		return false
	}

	switch {
	case t == rrtype.ANY && class == rrtype.ClassANY:
		if !hasName() {
			return wire.RCODENXDomain
		}
	case t == rrtype.ANY && class == rrtype.ClassNONE:
		if hasName() {
			return wire.RCODEYXDomain
		}
	case class == rrtype.ClassANY:
		if !hasType() {
			return wire.RCODENXRRSet
		}
	case class == rrtype.ClassNONE:
		if hasType() {
			return wire.RCODEYXRRSet
		}
	}
	return wire.RCODENoError
}

func (z *zoneIndex) applyUpdate(u wire.Record) {
	name := u.Name()
	t := u.Type()
	class := u.Class()
	switch class {
	case rrtype.ClassANY:
		// Delete RRset (or all RRsets if t == ANY).
		recs, ok := z.byName[nameKey(name)]
		if !ok {
			return
		}
		if t == rrtype.ANY {
			delete(z.byName, nameKey(name))
			return
		}
		kept := recs[:0]
		for _, r := range recs {
			if r.Type() != t {
				kept = append(kept, r)
			}
		}
		if len(kept) == 0 {
			delete(z.byName, nameKey(name))
		} else {
			z.byName[nameKey(name)] = kept
		}
	case rrtype.ClassNONE:
		// Delete specific record matching the rdata.
		recs, ok := z.byName[nameKey(name)]
		if !ok {
			return
		}
		target := u.RData()
		kept := recs[:0]
		for _, r := range recs {
			if r.Type() == t && rdataEqual(r.RData(), target) {
				continue
			}
			kept = append(kept, r)
		}
		if len(kept) == 0 {
			delete(z.byName, nameKey(name))
		} else {
			z.byName[nameKey(name)] = kept
		}
	default:
		// Add to RRset. NewRecordClass forces IN even if the wire said
		// otherwise — internal storage is class-IN.
		stored := wire.NewRecord(name, u.TTL(), u.RData())
		z.byName[nameKey(name)] = append(z.byName[nameKey(name)], stored)
		// Mark the name (and ancestors) as existing for wildcard logic.
		z.markExists(name)
	}
}

func (z *zoneIndex) markExists(n wire.Name) {
	cur := n
	for {
		z.namesExist[nameKey(cur)] = struct{}{}
		if cur.Equal(z.origin) {
			return
		}
		parent, ok := cur.Parent()
		if !ok {
			return
		}
		cur = parent
	}
}

// rdataEqual compares two rdata values by their wire representation.
func rdataEqual(a, b rdata.RData) bool {
	if a.Type() != b.Type() {
		return false
	}
	return bytes.Equal(rdata.Pack(a), rdata.Pack(b))
}
