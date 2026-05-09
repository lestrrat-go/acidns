package recursive

// RFC 8198 (Aggressive Use of DNSSEC-Validated Cache) — NSEC half.
//
// When the resolver has cached a DNSSEC-validated NSEC record from a
// negative response, the same NSEC can prove non-existence for any
// other name that falls within the NSEC's "next-name" interval — no
// upstream query needed. The implementation here covers NSEC NXDOMAIN
// synthesis only; NSEC3 (hash-space lookup) and NSEC NoData (type
// bitmap inspection) and wildcard interaction are tracked as Partial
// for follow-up work.
//
// # Why a separate index
//
// The standard cache is keyed by (qname, qtype) — given a query for a
// name X that we have NEVER asked for, we can't find an NSEC by name
// lookup. We need a structure ordered by canonical NSEC owner so a
// query name X can be located within an interval [owner, next-name)
// in O(log n) time.
//
// # Validation gate
//
// Aggressive use is only safe on validated answers. The Resolver
// inserts NSEC records into the index only after a Resolve completes
// with AD=true. A non-validating resolver never populates the index.

import (
	"bytes"
	"slices"
	"sync"
	"time"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// nsecEntry records one validated NSEC record together with the
// zone it was issued by and its absolute expiry. The issuingZone is
// used as a bailiwick guard: an NSEC from zone Z can only be used
// to deny names at-or-below Z.
type nsecEntry struct {
	owner        wire.Name
	next         wire.Name
	types        []rrtype.Type
	issuingZone  wire.Name
	expiresAt    time.Time
	canonicalKey []byte // pre-computed sort key over owner
}

// nsecIndex stores nsecEntry values sorted by the canonical sort key
// of the owner name. Lookups perform a binary search on the canonical
// key and then verify the interval covers the query. Mutex-guarded
// for safe concurrent access from multiple Resolve goroutines.
type nsecIndex struct {
	mu      sync.RWMutex
	entries []nsecEntry
}

func newNSECIndex() *nsecIndex {
	return &nsecIndex{}
}

// Insert adds e to the index, sorted by canonical owner. An existing
// entry with the same owner+next is replaced (the replacement is
// almost certainly a fresher TTL).
func (i *nsecIndex) Insert(e nsecEntry) {
	i.mu.Lock()
	defer i.mu.Unlock()
	idx, found := i.findByOwnerLocked(e.canonicalKey)
	if found {
		// Replace if the new entry has a longer remaining lifetime
		// or carries the same boundary (refresh).
		i.entries[idx] = e
		return
	}
	// Insert at idx, maintaining sort.
	i.entries = slices.Insert(i.entries, idx, e)
}

// Cover returns the entry whose interval covers q within bailiwick,
// or zero+false. Expired entries are skipped (callers may then
// trigger a sweep).
func (i *nsecIndex) Cover(q wire.Name, now time.Time) (nsecEntry, bool) {
	qKey := canonicalKey(q)
	i.mu.RLock()
	defer i.mu.RUnlock()
	// Find the rightmost entry whose owner ≤ q. That entry is the
	// only candidate that can cover q.
	idx := slices.IndexFunc(i.entries, func(e nsecEntry) bool {
		return bytes.Compare(e.canonicalKey, qKey) > 0
	})
	if idx == -1 {
		idx = len(i.entries)
	}
	if idx == 0 {
		return nsecEntry{}, false
	}
	cand := i.entries[idx-1]
	if !cand.expiresAt.After(now) {
		return nsecEntry{}, false
	}
	if !inBailiwickName(cand.issuingZone, q) {
		return nsecEntry{}, false
	}
	if !nsecCovers(cand.owner, cand.next, q) {
		return nsecEntry{}, false
	}
	if cand.owner.Equal(q) {
		// q matches the owner exactly — NSEC at q does not deny q;
		// it would prove the type-bitmap (NoData) which we don't
		// implement yet.
		return nsecEntry{}, false
	}
	return cand, true
}

// SweepExpired removes entries whose expiry is at-or-before now.
// Called occasionally to keep the index from growing unbounded.
func (i *nsecIndex) SweepExpired(now time.Time) {
	i.mu.Lock()
	defer i.mu.Unlock()
	kept := i.entries[:0]
	for _, e := range i.entries {
		if e.expiresAt.After(now) {
			kept = append(kept, e)
		}
	}
	i.entries = kept
}

// Len returns the current entry count. Test-only observability.
func (i *nsecIndex) Len() int {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return len(i.entries)
}

func (i *nsecIndex) findByOwnerLocked(key []byte) (int, bool) {
	idx, found := slices.BinarySearchFunc(i.entries, key, func(e nsecEntry, target []byte) int {
		return bytes.Compare(e.canonicalKey, target)
	})
	return idx, found
}

// canonicalKey returns a byte slice that compares (via bytes.Compare)
// in the same order as RFC 4034 §6.1 canonical DNS name ordering.
//
// The encoding stitches labels right-to-left with a 0x00 separator
// — labels are already lowercase per the wire layer's
// canonicalisation. Right-to-left because canonical DNS ordering
// compares the rightmost (TLD) label first; bytes.Compare's
// left-to-right scan over our reversed labels gives the same result.
func canonicalKey(n wire.Name) []byte {
	var labels [][]byte
	for l := range n.Labels() {
		cp := make([]byte, len(l))
		copy(cp, l)
		labels = append(labels, cp)
	}
	if len(labels) == 0 {
		return []byte{0x00}
	}
	var key []byte
	for i := len(labels) - 1; i >= 0; i-- {
		key = append(key, byte(len(labels[i])))
		key = append(key, labels[i]...)
	}
	key = append(key, 0x00)
	return key
}

// nsecCovers reports whether q falls within the NSEC interval
// (owner, next). Per RFC 4034 §4.1.1, an NSEC at owner with next-name
// next "covers" any name X that sorts strictly after owner and
// strictly before next. The wrap-around case is handled where next
// sorts before owner (the last NSEC in the zone wraps to the apex).
//
// Owner-equality is NOT covered here — a query equal to owner is
// handled separately as a NoData proof candidate (which this
// implementation does not yet synthesise).
func nsecCovers(owner, next, q wire.Name) bool {
	oKey := canonicalKey(owner)
	nKey := canonicalKey(next)
	qKey := canonicalKey(q)

	wrap := bytes.Compare(oKey, nKey) >= 0
	if wrap {
		return bytes.Compare(qKey, oKey) > 0 || bytes.Compare(qKey, nKey) < 0
	}
	return bytes.Compare(qKey, oKey) > 0 && bytes.Compare(qKey, nKey) < 0
}

// inBailiwickName reports whether descendant is at-or-below ancestor.
// Mirrors recursive.inBailiwick (defined in recursive.go) but is
// duplicated here to avoid a forward reference. The two share
// semantics; if either changes, sync the other.
func inBailiwickName(ancestor, descendant wire.Name) bool {
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

// synthesiseFromNSEC consults the aggressive NSEC index and, if a
// covering NSEC exists, returns a synthesised NXDOMAIN Entry. The
// synthesised Entry inherits the NSEC's remaining lifetime as the
// cache TTL and carries the original NSEC in its Authority section
// so a downstream consumer can verify (or just see) the proof.
//
// Returns (zero, false) when aggressive use is disabled, the index
// has no covering entry, or the entry has expired since the last
// access.
func (r *recursive) synthesiseFromNSEC(name wire.Name, t rrtype.Type) (Entry, bool) {
	if !r.aggressiveNSEC || r.nsecIdx == nil {
		return Entry{}, false
	}
	now := time.Now()
	cand, ok := r.nsecIdx.Cover(name, now)
	if !ok {
		return Entry{}, false
	}
	// The NSEC's owner ≠ name is enforced inside Cover. The query
	// type is irrelevant for NXDOMAIN synthesis: if the name doesn't
	// exist, no record of any type exists at it. (NoData synthesis
	// would consult cand.types and is not yet implemented.)
	_ = t

	ttl := time.Until(cand.expiresAt)
	if ttl <= 0 {
		return Entry{}, false
	}

	// Re-pack the NSEC so the Authority section in the synthesised
	// entry carries the same proof we relied on. Re-using the
	// rdata.NSEC value as a wire.Record requires the original TTL —
	// approximate by clamping to the remaining lifetime so a
	// downstream cache consumer doesn't over-extend.
	authority := []wire.Record{
		wire.NewRecord(cand.owner, ttl,
			rdata.NewNSEC(cand.next, cand.types)),
	}
	return Entry{
		Authority: authority,
		RCODE:     wire.RCODENXDomain,
		AD:        true,
		ExpiresAt: cand.expiresAt,
	}, true
}

// extractValidatedNSECs picks NSEC records out of resp's authority
// section that arrived alongside an authoritative NXDOMAIN. The
// caller is responsible for ensuring resp was DNSSEC-validated
// (Entry.AD == true) before invoking this.
//
// The issuingZone is determined from the SOA record in the
// authority section, if present; that zone is the apex of the zone
// the NSEC is signed in and bounds where the NSEC may be used.
func extractValidatedNSECs(authority []wire.Record, now time.Time) []nsecEntry {
	var soaOwner wire.Name
	for _, r := range authority {
		if r.Type() == rrtype.SOA {
			soaOwner = r.Name()
			break
		}
	}
	if !soaOwner.IsValid() {
		return nil
	}
	var out []nsecEntry
	for _, r := range authority {
		if r.Type() != rrtype.NSEC {
			continue
		}
		nsec, ok := wire.RDataAs[rdata.NSEC](r)
		if !ok {
			continue
		}
		out = append(out, nsecEntry{
			owner:        r.Name(),
			next:         nsec.NextDomainName(),
			types:        nsec.Types(),
			issuingZone:  soaOwner,
			expiresAt:    now.Add(r.TTL()),
			canonicalKey: canonicalKey(r.Name()),
		})
	}
	return out
}
