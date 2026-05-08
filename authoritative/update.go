package authoritative

import (
	"bytes"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// serveUpdate implements RFC 2136 dynamic update for an authoritative
// zone. The server is permissive: any caller able to send to the listener
// is granted update authority. Production deployments should layer a
// TSIG-aware ACL middleware in front of this handler.
func (a *authoritative) serveUpdate(w acidns.ResponseWriter, q wire.Message) {
	b := wire.NewBuilder().
		ID(q.ID()).
		Response(true).
		Opcode(wire.OpcodeUpdate)
	for _, qq := range q.Questions() {
		b = b.Question(qq)
	}

	if len(q.Questions()) != 1 {
		_ = w.WriteMsg(mustBuild(echoEDNS(b, q).RCODE(wire.RCODEFormErr), q))
		return
	}
	zoneQ := q.Questions()[0]
	if zoneQ.Type() != rrtype.SOA {
		_ = w.WriteMsg(mustBuild(echoEDNS(b, q).RCODE(wire.RCODEFormErr), q))
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	zone, ok := a.zones[nameKey(zoneQ.Name())]
	if !ok {
		_ = w.WriteMsg(mustBuild(echoEDNS(b, q).RCODE(wire.RCODENotAuth), q))
		return
	}

	// Prerequisites — RFC 2136 §3.2.
	for _, p := range q.Answers() {
		if rcode := zone.checkPrereq(p); rcode != wire.RCODENoError {
			_ = w.WriteMsg(mustBuild(echoEDNS(b, q).RCODE(rcode), q))
			return
		}
	}

	// Update — RFC 2136 §3.4.
	for _, u := range q.Authorities() {
		zone.applyUpdate(u)
	}
	_ = w.WriteMsg(mustBuild(echoEDNS(b, q), q))
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
