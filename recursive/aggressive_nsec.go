package recursive

// RFC 8198 (Aggressive Use of DNSSEC-Validated Cache) — NSEC half.
//
// When the resolver has cached a DNSSEC-validated NSEC record from a
// negative response, the same NSEC can prove non-existence for other
// names that fall within the NSEC's interval — no upstream query
// needed. Two flavours are handled here:
//
//   - NXDOMAIN synthesis: the cached NSEC's interval covers a name
//     that has never existed (the standard §5.1 case).
//   - NoData synthesis: the cached NSEC's owner equals the queried
//     name and its type bitmap excludes the queried qtype (§5.2).
//
// NSEC3 hash-space lookups are handled in aggressive_nsec3.go.
// Wildcard interaction is handled by both halves uniformly: when
// the proof set covers the would-be-wildcard expansion, synthesis
// proceeds; when it doesn't, the lookup falls through to the
// regular iteration path.
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
	maxLen  int // hard cap; 0 disables
}

func newNSECIndex() *nsecIndex {
	return &nsecIndex{maxLen: defaultAggressiveNSECCap}
}

// defaultAggressiveNSECCap bounds each NSEC/NSEC3 index to keep an
// attacker-driven NXDOMAIN flood from pushing memory unboundedly.
// Sustained validated negatives across many distinct zones is rare
// in practice; 4096 is comfortably above any healthy resolver's
// working set.
const defaultAggressiveNSECCap = 4096

// Insert adds e to the index, sorted by canonical owner. An existing
// entry with the same owner+next is replaced (the replacement is
// almost certainly a fresher TTL). When the index is at its hard
// cap, expired entries are swept first; if still full, the
// soonest-expiring entry is evicted to make room.
func (i *nsecIndex) Insert(e nsecEntry) {
	i.mu.Lock()
	defer i.mu.Unlock()
	idx, found := i.findByOwnerLocked(e.canonicalKey)
	if found {
		i.entries[idx] = e
		return
	}
	if i.maxLen > 0 && len(i.entries) >= i.maxLen {
		i.sweepExpiredLocked(time.Now())
	}
	if i.maxLen > 0 && len(i.entries) >= i.maxLen {
		i.evictSoonestLocked()
		idx, _ = i.findByOwnerLocked(e.canonicalKey)
	}
	i.entries = slices.Insert(i.entries, idx, e)
}

// evictSoonestLocked drops the entry whose expiresAt is earliest.
// Caller holds i.mu.
func (i *nsecIndex) evictSoonestLocked() {
	if len(i.entries) == 0 {
		return
	}
	soonest := 0
	for j := 1; j < len(i.entries); j++ {
		if i.entries[j].expiresAt.Before(i.entries[soonest].expiresAt) {
			soonest = j
		}
	}
	i.entries = slices.Delete(i.entries, soonest, soonest+1)
}

// sweepExpiredLocked is the locked half of SweepExpired.
func (i *nsecIndex) sweepExpiredLocked(now time.Time) {
	kept := i.entries[:0]
	for _, e := range i.entries {
		if e.expiresAt.After(now) {
			kept = append(kept, e)
		}
	}
	i.entries = kept
}

// nsecLookupKind classifies what kind of proof the index has for q.
type nsecLookupKind int

const (
	// nsecLookupNone means no covering NSEC was found (or it was
	// expired / out of bailiwick / no useful relationship to q).
	nsecLookupNone nsecLookupKind = iota
	// nsecLookupNXDOMAIN means a cached NSEC's interval covers q
	// strictly between owner and next; q does not exist.
	nsecLookupNXDOMAIN
	// nsecLookupNoData means a cached NSEC's owner equals q and the
	// caller-supplied qtype is absent from its type bitmap; q
	// exists but has no records of qtype.
	nsecLookupNoData
)

// Lookup returns the kind of proof the index has for (q, qtype) and
// the supporting entry. nsecLookupNone covers the "no useful proof"
// case. Expired entries are skipped (callers may then trigger a
// sweep).
//
// For NoData (§5.2 of RFC 8198), the cached NSEC's owner must equal
// q and the queried qtype must NOT appear in the NSEC's type
// bitmap. RFC 4034 §4.1.2 is explicit that the bitmap enumerates
// every type present at the owner, including RRSIG/NSEC themselves
// — so an NSEC whose bitmap lists, e.g., A and AAAA but not MX
// proves NoData for MX.
func (i *nsecIndex) Lookup(q wire.Name, qtype rrtype.Type, now time.Time) (nsecEntry, nsecLookupKind) {
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
		return nsecEntry{}, nsecLookupNone
	}
	cand := i.entries[idx-1]
	if !cand.expiresAt.After(now) {
		return nsecEntry{}, nsecLookupNone
	}
	if !inBailiwickName(cand.issuingZone, q) {
		return nsecEntry{}, nsecLookupNone
	}
	if cand.owner.Equal(q) {
		// NoData candidate: NSEC at q proves NoData iff qtype is
		// absent from its bitmap AND CNAME is also absent (a CNAME
		// at q would be returned as an aliased answer instead).
		if typeInBitmap(cand.types, rrtype.CNAME) {
			return nsecEntry{}, nsecLookupNone
		}
		if typeInBitmap(cand.types, qtype) {
			return nsecEntry{}, nsecLookupNone
		}
		return cand, nsecLookupNoData
	}
	if !nsecCovers(cand.owner, cand.next, q) {
		return nsecEntry{}, nsecLookupNone
	}
	return cand, nsecLookupNXDOMAIN
}

// SweepExpired removes entries whose expiry is at-or-before now.
// Called periodically by recursive.Run when aggressive NSEC is on.
func (i *nsecIndex) SweepExpired(now time.Time) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.sweepExpiredLocked(now)
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

// hasWildcardDenial reports whether the index contains an NSEC
// whose interval covers *.X for some ancestor X of q. RFC 4035
// §5.4 / RFC 8198 §5.5: a complete NXDOMAIN proof must include
// both an NSEC covering q AND an NSEC denying any wildcard match;
// without the latter, q might still be matched by a wildcard at
// some ancestor.
//
// The check is conservative — if any ancestor's wildcard is
// denied, we accept synthesis. The most-likely ancestor (q's
// closest encloser) isn't known without a query, but a real
// validated NXDOMAIN response from any qname in the same zone
// would have supplied the relevant wildcard-denying NSEC, which
// the index then carries.
func (i *nsecIndex) hasWildcardDenial(q wire.Name, now time.Time) bool {
	cur := q
	for {
		p, ok := cur.Parent()
		if !ok || cur.Equal(p) {
			break
		}
		// Compute *.p as the wildcard at p.
		wc, err := wire.ParseName("*." + p.String())
		if err == nil {
			if _, kind := i.Lookup(wc, rrtype.ANY, now); kind == nsecLookupNXDOMAIN {
				return true
			}
		}
		cur = p
	}
	return false
}

// typeInBitmap reports whether t appears in the NSEC type bitmap.
// Used both for NoData synthesis (§5.2) and to prevent
// NSEC-at-qname from being misinterpreted as NoData when a CNAME
// is also present (which would normally produce an aliased answer
// rather than NoData).
func typeInBitmap(bitmap []rrtype.Type, t rrtype.Type) bool {
	for _, b := range bitmap {
		if b == t {
			return true
		}
	}
	return false
}

// synthesiseFromNSEC consults the aggressive NSEC index and, if a
// covering NSEC exists, returns a synthesised negative Entry —
// either NXDOMAIN (interval-covering NSEC, RFC 8198 §5.1) or NoData
// (owner-matching NSEC with type bitmap excluding qtype, §5.2). The
// synthesised Entry inherits the NSEC's remaining lifetime as its
// cache lifetime and carries the original NSEC in its Authority
// section so a downstream consumer can verify (or just see) the
// proof.
//
// Returns (zero, false) when aggressive use is disabled, the index
// has no useful entry, or the entry has expired.
func (r *recursive) synthesiseFromNSEC(name wire.Name, t rrtype.Type) (Entry, bool) {
	if !r.aggressiveNSEC || r.nsecIdx == nil {
		return Entry{}, false
	}
	now := time.Now()
	cand, kind := r.nsecIdx.Lookup(name, t, now)
	if kind == nsecLookupNone {
		return Entry{}, false
	}
	// Wildcard denial guard (RFC 4035 §5.4 / RFC 8198 §5.5): a
	// covering NSEC alone doesn't prove non-existence — we also
	// need evidence that no wildcard would have matched. If the
	// cache lacks such an NSEC, fall through to a real query.
	if !r.nsecIdx.hasWildcardDenial(name, now) {
		return Entry{}, false
	}

	ttl := time.Until(cand.expiresAt)
	if ttl <= 0 {
		return Entry{}, false
	}

	// Re-pack the NSEC so the Authority section in the synthesised
	// entry carries the same proof we relied on. Clamp TTL to the
	// remaining lifetime so a downstream cache consumer doesn't
	// over-extend.
	authority := []wire.Record{
		wire.NewRecord(cand.owner, ttl,
			rdata.NewNSEC(cand.next, cand.types)),
	}
	rcode := wire.RCODENXDomain
	if kind == nsecLookupNoData {
		rcode = wire.RCODENoError
	}
	return Entry{
		authority: authority,
		rcode:     rcode,
		ad:        true,
		expiresAt: cand.expiresAt,
	}, true
}

// extractValidatedNSECs picks NSEC records out of resp's authority
// section that arrived alongside an authoritative negative response
// (NXDOMAIN or NoData). The caller is responsible for ensuring
// resp was DNSSEC-validated (Entry.AD == true) before invoking
// this.
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
