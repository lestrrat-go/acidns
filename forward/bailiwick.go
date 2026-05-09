package forward

import (
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// filterBailiwick drops upstream-supplied records that are unrelated
// to the original question name. A configured forwarder trusts its
// upstream, but cache-poisoning attacks (Kashpureff-style and
// modern variants) work by stuffing answers for OTHER names into
// the response — a defensive forwarder should not relay those to
// downstream clients or admit them to the cache.
//
// The filter is intentionally simpler than [recursive.bailiwickFilter]:
// the recursive resolver classifies authority and additional records
// against zone-cuts derived from delegations it walked itself; a
// forwarder has no such walk and so must rely on the qname alone.
//
// Rules:
//
//   - Answer: keep records whose owner is qname or a CNAME-chain
//     target rooted at qname (transitive). All other Answer records
//     are dropped.
//   - Authority: keep records whose owner is at-or-above qname
//     (parent zones are legitimate sources of NS/SOA/RRSIG for the
//     query). Records owned by unrelated names are dropped.
//   - Additional: keep OPT pseudo-RRs and records whose owner is
//     referenced by a kept Answer-section CNAME target or kept
//     Authority-section NS rdata. A/AAAA glue for unrelated names
//     is dropped.
//
// The function returns a new wire.Message with the filtered
// sections, preserving header bits and EDNS option set. The
// message ID, flags, and original question are inherited from
// the supplied response so callers can drop in the filtered value.
func filterBailiwick(qname wire.Name, resp wire.Message) wire.Message {
	chain := map[string]struct{}{nameKey(qname): {}}
	// Iterate until no new CNAME target is added — the chain is
	// bounded by the answer count, no need for a separate hop cap.
	for {
		grew := false
		for _, r := range resp.Answers() {
			if r.Type() != rrtype.CNAME {
				continue
			}
			if _, ok := chain[nameKey(r.Name())]; !ok {
				continue
			}
			c, ok := wire.RDataAs[rdata.CNAME](r)
			if !ok {
				continue
			}
			tk := nameKey(c.Target())
			if _, exists := chain[tk]; exists {
				continue
			}
			chain[tk] = struct{}{}
			grew = true
		}
		if !grew {
			break
		}
	}

	keptAnswers := make([]wire.Record, 0, len(resp.Answers()))
	for _, r := range resp.Answers() {
		if _, ok := chain[nameKey(r.Name())]; ok {
			keptAnswers = append(keptAnswers, r)
		}
	}

	keptAuthority := make([]wire.Record, 0, len(resp.Authorities()))
	for _, r := range resp.Authorities() {
		if isAtOrAbove(r.Name(), qname) {
			keptAuthority = append(keptAuthority, r)
		}
	}

	referenced := map[string]struct{}{}
	for _, r := range keptAnswers {
		if c, ok := wire.RDataAs[rdata.CNAME](r); ok {
			referenced[nameKey(c.Target())] = struct{}{}
		}
	}
	for _, r := range keptAuthority {
		if ns, ok := wire.RDataAs[rdata.NS](r); ok {
			referenced[nameKey(ns.NSDName())] = struct{}{}
		}
	}

	keptAdditional := make([]wire.Record, 0, len(resp.Additionals()))
	for _, r := range resp.Additionals() {
		if r.Type() == rrtype.OPT {
			keptAdditional = append(keptAdditional, r)
			continue
		}
		if _, ok := referenced[nameKey(r.Name())]; ok {
			keptAdditional = append(keptAdditional, r)
		}
	}

	b := wire.NewMessageBuilder().ID(resp.ID()).Flags(resp.Flags())
	for _, qq := range resp.Questions() {
		b = b.Question(qq)
	}
	for _, r := range keptAnswers {
		b = b.Answer(r)
	}
	for _, r := range keptAuthority {
		b = b.Authority(r)
	}
	for _, r := range keptAdditional {
		b = b.Additional(r)
	}
	if e, ok := resp.EDNS(); ok {
		b = b.EDNS(e)
	}
	out, err := b.Build()
	if err != nil {
		return resp // fall back to the unfiltered response if rebuild fails
	}
	return out
}

// isAtOrAbove reports whether ancestor is the owner of, or a parent
// zone of, descendant. Used to keep authority records that are
// legitimately produced by a parent zone in the qname's hierarchy.
func isAtOrAbove(ancestor, descendant wire.Name) bool {
	cur := descendant
	for cur.IsValid() {
		if cur.Equal(ancestor) {
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

// nameKey returns a canonical map key for n. Mirrors the helper
// recursive uses so the two filters stay structurally identical.
func nameKey(n wire.Name) string {
	return string(n.AppendWire(nil))
}
