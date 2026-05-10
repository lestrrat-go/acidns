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
func (a *Authoritative) serveUpdate(ctx context.Context, w acidns.ResponseWriter, q wire.Message) {
	b := wire.NewMessageBuilder().
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
	zoneName := zoneQ.Name()

	// Cap the per-UPDATE record count before policy invocation. Hitting
	// the cap is treated as malformed input rather than a policy
	// failure — the operator's policy should not have to count records.
	if a.maxUpdateRecords > 0 && len(q.Answers())+len(q.Authorities()) > a.maxUpdateRecords {
		_ = w.WriteMsg(mustBuild(setRCODE(b, q, wire.RCODEFormErr), q))
		return
	}

	// Authorisation gate. With no policy installed, every UPDATE is
	// refused — we won't accept unauthenticated mutation by default.
	if a.updatePolicy == nil || !a.updatePolicy(ctx, w, q) {
		_ = w.WriteMsg(mustBuild(setRCODE(b, q, wire.RCODERefused), q))
		return
	}

	// RFC 2136 §3.4.2.4: every record in the prerequisite and update
	// sections must lie within the zone the request targets. A signed
	// UPDATE for `victim.example` zone that carries an out-of-zone
	// record like `evil.com IN A …` would otherwise be admitted into
	// the zone's index, leaking via AXFR or shadowing legitimate data.
	for _, p := range q.Answers() {
		if !inBailiwick(zoneName, p.Name()) {
			_ = w.WriteMsg(mustBuild(setRCODE(b, q, wire.RCODENotZone), q))
			return
		}
	}
	for _, u := range q.Authorities() {
		if !inBailiwick(zoneName, u.Name()) {
			_ = w.WriteMsg(mustBuild(setRCODE(b, q, wire.RCODENotZone), q))
			return
		}
	}

	// Prerequisite scan under a read lock so concurrent queries continue
	// during the (potentially expensive) check. A *zoneIndex is treated
	// as immutable once published, so a snapshot taken under RLock
	// remains a self-consistent view even after the lock is released.
	a.mu.RLock()
	zone, ok := a.zones[nameKey(zoneName)]
	if !ok {
		a.mu.RUnlock()
		_ = w.WriteMsg(mustBuild(setRCODE(b, q, wire.RCODENotAuth), q))
		return
	}
	if rcode := evaluatePrereqs(zone, q.Answers()); rcode != wire.RCODENoError {
		a.mu.RUnlock()
		_ = w.WriteMsg(mustBuild(setRCODE(b, q, rcode), q))
		return
	}
	if rcode := validateUpdates(zone, q.Authorities()); rcode != wire.RCODENoError {
		a.mu.RUnlock()
		_ = w.WriteMsg(mustBuild(setRCODE(b, q, rcode), q))
		return
	}
	a.mu.RUnlock()

	// Promote to write lock. The published *zoneIndex may have been
	// swapped between RUnlock and Lock by a competing UPDATE, so we
	// re-fetch the current pointer and re-validate the prerequisites
	// against it. Without the recheck, a racing UPDATE that satisfied
	// or invalidated a prerequisite could be papered over by this one.
	a.mu.Lock()
	zone, ok = a.zones[nameKey(zoneName)]
	if !ok {
		a.mu.Unlock()
		_ = w.WriteMsg(mustBuild(setRCODE(b, q, wire.RCODENotAuth), q))
		return
	}
	if rcode := evaluatePrereqs(zone, q.Answers()); rcode != wire.RCODENoError {
		a.mu.Unlock()
		_ = w.WriteMsg(mustBuild(setRCODE(b, q, rcode), q))
		return
	}
	if rcode := validateUpdates(zone, q.Authorities()); rcode != wire.RCODENoError {
		a.mu.Unlock()
		_ = w.WriteMsg(mustBuild(setRCODE(b, q, rcode), q))
		return
	}

	// Apply — RFC 2136 §3.4. Copy-on-write: mutate a clone and swap the
	// pointer atomically under the write lock. Readers that snapshotted
	// the previous *zoneIndex via findZone continue against an immutable
	// view, so a query in flight cannot race with the in-place map writes
	// applyUpdate would otherwise perform.
	newZone := zone.clone()
	changed := false
	for _, u := range q.Authorities() {
		if newZone.applyUpdate(u) {
			changed = true
		}
	}

	var oldSerial, newSerial uint32
	if soa, ok := wire.RDataAs[rdata.SOA](newZone.soaRec); ok {
		oldSerial = soa.Serial()
		newSerial = oldSerial
	}
	if changed {
		// RFC 2136 §3.7: bump SOA serial on any change-effecting update.
		// uint32 wrap is the natural RFC 1982 behaviour — an authoritative
		// server that rolls 0xFFFFFFFF → 0x00000000 stays consistent under
		// serial-number arithmetic.
		newZone.bumpSOA()
		// Deletes can leave dangling entries in namesExist; rebuild it from
		// the current byName so wildcard synthesis stays correct.
		newZone.rebuildNamesExist()
		if soa, ok := wire.RDataAs[rdata.SOA](newZone.soaRec); ok {
			newSerial = soa.Serial()
		}
	}
	a.zones[nameKey(zoneName)] = newZone
	a.mu.Unlock()

	_ = w.WriteMsg(mustBuild(echoEDNS(b, q), q))

	if changed && a.onUpdate != nil {
		a.onUpdate(ctx, zoneName, oldSerial, newSerial)
	}
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

// evaluatePrereqs walks the prerequisite section (q.Answers) and returns
// the first failing RCODE, or RCODENoError if every prerequisite
// matches. Implements the cases from RFC 2136 §3.2.
//
// A class-IN prereq (with rdata) participates in the §2.4.2
// value-dependent comparison. Such records are gathered by (name,
// type) and the resulting RRsets must be wire-equal to the zone's
// RRsets at those same coordinates; otherwise NXRRSet.
func evaluatePrereqs(z *zoneIndex, prereqs []wire.Record) wire.RCODE {
	type rrkey struct {
		name string
		typ  rrtype.Type
	}
	want := make(map[rrkey]map[string]struct{})
	for _, p := range prereqs {
		// RFC 2136 §3.2.1 / §3.2.2 / §3.2.3 / §3.2.4: TTL must be 0 on
		// every prerequisite RR.
		if p.TTL() != 0 {
			return wire.RCODEFormErr
		}
		t := p.Type()
		class := p.Class()
		switch class {
		case rrtype.ClassANY:
			// rdata must be empty for class-ANY prereqs.
			if hasRData(p) {
				return wire.RCODEFormErr
			}
			if t == rrtype.ANY {
				if !z.hasName(p.Name()) {
					return wire.RCODENXDomain
				}
				continue
			}
			if !z.hasType(p.Name(), t) {
				return wire.RCODENXRRSet
			}
		case rrtype.ClassNONE:
			if hasRData(p) {
				return wire.RCODEFormErr
			}
			if t == rrtype.ANY {
				if z.hasName(p.Name()) {
					return wire.RCODEYXDomain
				}
				continue
			}
			if z.hasType(p.Name(), t) {
				return wire.RCODEYXRRSet
			}
		case rrtype.ClassIN:
			// §2.4.2 value-dependent: collect for set comparison.
			k := rrkey{name: nameKey(p.Name()), typ: t}
			set, ok := want[k]
			if !ok {
				set = make(map[string]struct{})
				want[k] = set
			}
			set[string(rdata.Pack(p.RData()))] = struct{}{}
		default:
			// §3.2.5: prereq class outside {zoneClass, ANY, NONE} is malformed.
			return wire.RCODEFormErr
		}
	}
	for k, set := range want {
		recs, ok := z.byName[k.name]
		if !ok {
			return wire.RCODENXRRSet
		}
		got := make(map[string]struct{})
		for _, r := range recs {
			if r.Type() != k.typ {
				continue
			}
			got[string(rdata.Pack(r.RData()))] = struct{}{}
		}
		if len(got) != len(set) {
			return wire.RCODENXRRSet
		}
		for v := range set {
			if _, ok := got[v]; !ok {
				return wire.RCODENXRRSet
			}
		}
	}
	return wire.RCODENoError
}

// validateUpdates structurally checks the update section (q.Authorities)
// against RFC 2136 §3.4.2 / §3.4.2.3 / §3.4.2.4. Names have already been
// bailiwick-checked by the caller; this catches malformed class/TTL
// shapes and the apex-CNAME/DNAME prohibition before any mutation runs.
func validateUpdates(z *zoneIndex, updates []wire.Record) wire.RCODE {
	for _, u := range updates {
		t := u.Type()
		class := u.Class()
		switch class {
		case rrtype.ClassANY:
			// Delete RRset (or all RRsets when TYPE=ANY): TTL=0,
			// rdlength=0.
			if u.TTL() != 0 || hasRData(u) {
				return wire.RCODEFormErr
			}
		case rrtype.ClassNONE:
			// Delete specific record: TTL=0, rdata present (the value
			// to match).
			if u.TTL() != 0 || !hasRData(u) {
				return wire.RCODEFormErr
			}
		case rrtype.ClassIN:
			// Add. Apex CNAME/DNAME co-located with SOA breaks RFC 1034
			// §3.6.2 ("if a CNAME RR is present at a node, no other
			// data should be present"). Reject the entire UPDATE rather
			// than silently corrupting the zone.
			if u.Name().Equal(z.origin) && (t == rrtype.CNAME || t == rrtype.DNAME) {
				return wire.RCODEFormErr
			}
		default:
			// §3.4.2.3: a class outside {zone-class, ANY, NONE} is malformed.
			return wire.RCODEFormErr
		}
	}
	return wire.RCODENoError
}

// hasName reports whether the zone currently has any records (or a
// registered empty-non-terminal) at name.
func (z *zoneIndex) hasName(name wire.Name) bool {
	_, ok := z.byName[nameKey(name)]
	return ok
}

// hasType reports whether the zone has at least one RR of type t at name.
func (z *zoneIndex) hasType(name wire.Name, t rrtype.Type) bool {
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

// hasRData reports whether r carries any rdata (rdlength > 0). Used by
// the §3.2 / §3.4 structural shape checks: class-ANY prereqs require
// empty rdata, class-NONE updates require non-empty rdata, etc.
func hasRData(r wire.Record) bool {
	return len(rdata.Pack(r.RData())) > 0
}

// inBailiwick reports whether name is at-or-below origin. Mirrors the
// recursive package's helper of the same name; duplicated here so the
// authoritative package does not import recursive (cyclic) and so the
// test suites stay independent.
func inBailiwick(origin, name wire.Name) bool {
	cur := name
	for cur.IsValid() {
		if cur.Equal(origin) {
			return true
		}
		p, ok := cur.Parent()
		if !ok || cur.Equal(p) {
			return false
		}
		cur = p
	}
	return false
}

// applyUpdate mutates z according to a single record from the UPDATE
// section. Returns true when the mutation actually changed zone state
// (so the caller can decide whether to bump SOA / fire OnUpdate).
// Idempotent operations (deleting a non-existent record, adding a
// duplicate of an existing one) return false.
func (z *zoneIndex) applyUpdate(u wire.Record) bool {
	name := u.Name()
	t := u.Type()
	class := u.Class()
	switch class {
	case rrtype.ClassANY:
		// Delete RRset (or all RRsets if t == ANY).
		recs, ok := z.byName[nameKey(name)]
		if !ok {
			return false
		}
		// RFC 2136 §3.4.2.4: deleting the apex SOA or apex NS via this
		// path would leave the zone unservable; ignore those silently
		// so an attacker with UPDATE rights can't take the zone down by
		// asking for "delete RRset SOA" at the apex.
		if name.Equal(z.origin) && (t == rrtype.SOA || t == rrtype.NS || t == rrtype.ANY) {
			if t == rrtype.ANY {
				// "delete everything at the apex" — keep SOA + NS.
				kept := recs[:0]
				changed := false
				for _, r := range recs {
					if r.Type() == rrtype.SOA || r.Type() == rrtype.NS {
						kept = append(kept, r)
						continue
					}
					changed = true
				}
				if !changed {
					return false
				}
				if len(kept) == 0 {
					delete(z.byName, nameKey(name))
				} else {
					z.byName[nameKey(name)] = kept
				}
				return true
			}
			return false
		}
		if t == rrtype.ANY {
			delete(z.byName, nameKey(name))
			return true
		}
		kept := recs[:0]
		removed := false
		for _, r := range recs {
			if r.Type() == t {
				removed = true
				continue
			}
			kept = append(kept, r)
		}
		if !removed {
			return false
		}
		if len(kept) == 0 {
			delete(z.byName, nameKey(name))
		} else {
			z.byName[nameKey(name)] = kept
		}
		return true
	case rrtype.ClassNONE:
		// Delete specific record matching the rdata.
		recs, ok := z.byName[nameKey(name)]
		if !ok {
			return false
		}
		// Same apex-protection as ClassANY above for SOA/NS removal.
		if name.Equal(z.origin) && (t == rrtype.SOA || t == rrtype.NS) {
			return false
		}
		target := u.RData()
		kept := recs[:0]
		removed := false
		for _, r := range recs {
			if r.Type() == t && rdataEqual(r.RData(), target) {
				removed = true
				continue
			}
			kept = append(kept, r)
		}
		if !removed {
			return false
		}
		if len(kept) == 0 {
			delete(z.byName, nameKey(name))
		} else {
			z.byName[nameKey(name)] = kept
		}
		return true
	default:
		// Add. NewRecordClass forces IN even if the wire said otherwise —
		// internal storage is class-IN.
		stored := wire.NewRecord(name, u.TTL(), u.RData())
		// Idempotent add: an exact duplicate should not bump SOA.
		for _, r := range z.byName[nameKey(name)] {
			if r.Type() == t && r.TTL() == u.TTL() && rdataEqual(r.RData(), u.RData()) {
				return false
			}
		}
		// Apex SOA replacement: the new RR replaces the old in place
		// and updates z.soaRec so subsequent answers carry the new
		// values. The serial in this added SOA wins (RFC 2136 §3.6).
		if name.Equal(z.origin) && t == rrtype.SOA {
			recs := z.byName[nameKey(name)]
			out := recs[:0]
			for _, r := range recs {
				if r.Type() == rrtype.SOA {
					continue
				}
				out = append(out, r)
			}
			out = append(out, stored)
			z.byName[nameKey(name)] = out
			z.soaRec = stored
			z.markExists(name)
			return true
		}
		z.byName[nameKey(name)] = append(z.byName[nameKey(name)], stored)
		// Mark the name (and ancestors) as existing for wildcard logic.
		z.markExists(name)
		return true
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

// rebuildNamesExist regenerates z.namesExist from z.byName. Deletes can
// leave a name in namesExist with no descendant in byName, which would
// cause wildcard synthesis at that name to incorrectly resolve to ENT
// NODATA instead of falling through to *.encloser. The cost is O(N) per
// UPDATE-with-deletes; rebuilding is simpler than the alternative
// (refcount per ancestor) and stays correct under arbitrary delete
// orderings.
func (z *zoneIndex) rebuildNamesExist() {
	out := make(map[string]struct{}, len(z.byName))
	for _, recs := range z.byName {
		if len(recs) == 0 {
			continue
		}
		owner := recs[0].Name()
		cur := owner
		for {
			out[nameKey(cur)] = struct{}{}
			if cur.Equal(z.origin) {
				break
			}
			parent, ok := cur.Parent()
			if !ok {
				break
			}
			cur = parent
		}
	}
	// The zone origin always exists (apex SOA/NS), even if every
	// other name has been deleted.
	out[nameKey(z.origin)] = struct{}{}
	z.namesExist = out
}

// bumpSOA increments the apex SOA serial by 1 (uint32 wrap) and
// rewrites z.soaRec plus the corresponding entry in z.byName. Called
// after any UPDATE that mutated zone data, per RFC 2136 §3.7.
func (z *zoneIndex) bumpSOA() {
	soa, ok := wire.RDataAs[rdata.SOA](z.soaRec)
	if !ok {
		return
	}
	bumped, err := rdata.NewSOA(
		soa.MName(), soa.RName(),
		soa.Serial()+1,
		soa.Refresh(), soa.Retry(), soa.Expire(), soa.Minimum(),
	)
	if err != nil {
		return
	}
	newRec := wire.NewRecord(z.soaRec.Name(), z.soaRec.TTL(), bumped)
	z.soaRec = newRec
	// Replace the apex SOA in byName.
	apexKey := nameKey(z.origin)
	recs := z.byName[apexKey]
	out := make([]wire.Record, 0, len(recs))
	replaced := false
	for _, r := range recs {
		if !replaced && r.Type() == rrtype.SOA {
			out = append(out, newRec)
			replaced = true
			continue
		}
		out = append(out, r)
	}
	if !replaced {
		out = append(out, newRec)
	}
	z.byName[apexKey] = out
}

// rdataEqual compares two rdata values by their wire representation.
func rdataEqual(a, b rdata.RData) bool {
	if a.Type() != b.Type() {
		return false
	}
	return bytes.Equal(rdata.Pack(a), rdata.Pack(b))
}
