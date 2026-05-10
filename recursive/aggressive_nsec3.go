package recursive

// RFC 8198 — NSEC3 half. Hash-space lookups, closest-encloser
// proofs, and opt-out enforcement.
//
// # Why NSEC3 is harder than NSEC
//
// NSEC orders names canonically; NSEC3 orders the *hashes* of names
// under per-zone (alg, iterations, salt) parameters. To use a
// cached NSEC3 to deny qname, we must:
//
//  1. Know the zone's NSEC3 parameters (recorded when we cached
//     records from that zone).
//  2. Hash candidate names (qname itself for NoData; qname's
//     ancestors for the closest-encloser walk).
//  3. Match or cover those hashes against entries in the index.
//
// # Closest-encloser proof for NXDOMAIN (RFC 5155 §8.4)
//
// Three NSEC3 records together prove qname does not exist:
//
//   - One whose owner-hash equals H(closest_encloser): proves the
//     encloser exists (any NSEC3 implies the owner exists).
//   - One whose interval covers H(next_closer_name): proves the
//     name immediately below the encloser does not exist.
//   - One whose interval covers H(*.<closest_encloser>): proves no
//     wildcard match.
//
// A response that originally proved NXDOMAIN typically supplies
// all three; aggressive synthesis tries to assemble the same
// triple from the cache for a different qname whose closest
// encloser turns out to be the same.
//
// # Opt-out (RFC 5155 §6 / RFC 8198 §5.6)
//
// An NSEC3 with the opt-out flag set does not prove the absence of
// names in its interval — only the absence of *signed delegations*.
// Aggressive synthesis must refuse to use any opt-out NSEC3 as a
// covering proof.

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // RFC 5155 §5 fixes the hash algorithm at SHA-1.
	"slices"
	"sync"
	"time"

	"github.com/lestrrat-go/acidns/dnssec/validator/validatorbb"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// nsec3HashSHA1 deprecated alias kept for narrow internal use; new code
// should use [rdata.NSEC3HashSHA1].
//
// nsec3HashSHA1 is the only NSEC3 hash algorithm registered with
// IANA (RFC 5155 §11.2). Cached records with any other algorithm
// are not usable for synthesis.
const nsec3HashSHA1 = rdata.NSEC3HashSHA1

// maxNSEC3Iterations matches the validator's bound (RFC 9276 §3.1).
// A cached NSEC3 with a higher count is dropped — we couldn't have
// validated it in the first place under the project's policy, so
// it cannot be in the index from a Secure response.
const maxNSEC3Iterations uint16 = 100

// nsec3Params bundles the (alg, iterations, salt) tuple that all
// NSEC3 records in a single zone share (RFC 5155 §4.1).
type nsec3Params struct {
	alg        rdata.NSEC3HashAlgorithm
	iterations uint16
	salt       []byte
}

func (p nsec3Params) equal(o nsec3Params) bool {
	return p.alg == o.alg && p.iterations == o.iterations && bytes.Equal(p.salt, o.salt)
}

// nsec3Entry stores one validated NSEC3 record together with its
// pre-extracted owner hash. Indexed by ownerHash.
type nsec3Entry struct {
	ownerHash []byte
	nextHash  []byte
	types     []rrtype.Type
	optOut    bool
	expiresAt time.Time
}

// nsec3ZoneIndex holds the NSEC3 entries for a single zone, sorted
// by ownerHash. Each zone has its own nsec3Params (entries cached
// before a parameter change are dropped on the next insert with
// new params).
type nsec3ZoneIndex struct {
	params  nsec3Params
	entries []nsec3Entry
}

// nsec3Index aggregates per-zone NSEC3 hash-space indexes keyed by
// the canonical wire form of the zone apex.
type nsec3Index struct {
	mu     sync.RWMutex
	zones  map[string]*nsec3ZoneIndex
	maxLen int // total entries across all zones; 0 disables
}

func newNSEC3Index() *nsec3Index {
	return &nsec3Index{
		zones:  make(map[string]*nsec3ZoneIndex),
		maxLen: defaultAggressiveNSECCap,
	}
}

// totalLocked returns the total number of NSEC3 entries across all
// zones. Caller holds i.mu.
func (i *nsec3Index) totalLocked() int {
	n := 0
	for _, z := range i.zones {
		n += len(z.entries)
	}
	return n
}

// SweepExpired removes expired NSEC3 entries from every zone.
// Empty zones are dropped. Called periodically by recursive.Run
// when aggressive NSEC is on.
func (i *nsec3Index) SweepExpired(now time.Time) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.sweepExpiredLocked(now)
}

func (i *nsec3Index) sweepExpiredLocked(now time.Time) {
	for k, z := range i.zones {
		kept := z.entries[:0]
		for _, e := range z.entries {
			if e.expiresAt.After(now) {
				kept = append(kept, e)
			}
		}
		z.entries = kept
		if len(z.entries) == 0 {
			delete(i.zones, k)
		}
	}
}

// evictSoonestLocked picks the soonest-expiring entry across all
// zones and removes it. Used when the hard cap is hit and a sweep
// did not free space.
func (i *nsec3Index) evictSoonestLocked() {
	var soonestZone string
	soonestIdx := -1
	var soonestAt time.Time
	for k, z := range i.zones {
		for j, e := range z.entries {
			if soonestIdx == -1 || e.expiresAt.Before(soonestAt) {
				soonestZone = k
				soonestIdx = j
				soonestAt = e.expiresAt
			}
		}
	}
	if soonestIdx == -1 {
		return
	}
	z := i.zones[soonestZone]
	z.entries = slices.Delete(z.entries, soonestIdx, soonestIdx+1)
	if len(z.entries) == 0 {
		delete(i.zones, soonestZone)
	}
}

// Insert adds e to the index under zoneApex's bucket. If params
// differ from a previous insert in the same zone, the bucket is
// reset — a parameter change on the authoritative side invalidates
// every cached entry under the old params. When the global hard cap
// is reached, expired entries are swept first; if still full, the
// soonest-expiring entry across all zones is evicted.
func (i *nsec3Index) Insert(zoneApex wire.Name, params nsec3Params, e nsec3Entry) {
	if params.alg != nsec3HashSHA1 || params.iterations > maxNSEC3Iterations {
		return
	}
	key := nameKey(zoneApex)
	i.mu.Lock()
	defer i.mu.Unlock()
	z, ok := i.zones[key]
	if !ok || !z.params.equal(params) {
		z = &nsec3ZoneIndex{params: params}
		i.zones[key] = z
	}
	idx, found := slices.BinarySearchFunc(z.entries, e.ownerHash,
		func(x nsec3Entry, target []byte) int { return bytes.Compare(x.ownerHash, target) })
	if found {
		z.entries[idx] = e
		return
	}
	if i.maxLen > 0 && i.totalLocked() >= i.maxLen {
		i.sweepExpiredLocked(time.Now())
	}
	if i.maxLen > 0 && i.totalLocked() >= i.maxLen {
		i.evictSoonestLocked()
		// zone may have been deleted during eviction; rehydrate.
		z, ok = i.zones[key]
		if !ok {
			z = &nsec3ZoneIndex{params: params}
			i.zones[key] = z
		}
		idx, _ = slices.BinarySearchFunc(z.entries, e.ownerHash,
			func(x nsec3Entry, target []byte) int { return bytes.Compare(x.ownerHash, target) })
	}
	z.entries = slices.Insert(z.entries, idx, e)
}

// nsec3Lookup attempts to assemble a §5.3/§5.4 proof for (q, qtype)
// using cached NSEC3 records. The zoneApex argument is the
// authoritative zone the resolver believes covers q. Returns the
// proof kind and the supporting entries (zero, none) when no proof
// can be assembled.
//
// The supporting entries are returned for inclusion in the
// synthesised Authority section so a downstream consumer can
// verify (or just see) the same proof we relied on.
func (i *nsec3Index) Lookup(zoneApex, q wire.Name, qtype rrtype.Type, now time.Time) ([]nsec3Entry, nsec3Params, nsecLookupKind) {
	key := nameKey(zoneApex)
	i.mu.RLock()
	defer i.mu.RUnlock()
	z, ok := i.zones[key]
	if !ok {
		return nil, nsec3Params{}, nsecLookupNone
	}
	// 1. NoData: NSEC3 owner-hash matching H(q), bitmap excluding qtype.
	if entry, found := i.matchHashLocked(z, q, now); found {
		if !typeInBitmap(entry.types, rrtype.CNAME) && !typeInBitmap(entry.types, qtype) {
			return []nsec3Entry{entry}, z.params, nsecLookupNoData
		}
	}
	// 2. NXDOMAIN: closest-encloser + next-closer-cover + wildcard-cover.
	if proofs, found := i.closestEncloserProofLocked(z, q, now); found {
		return proofs, z.params, nsecLookupNXDOMAIN
	}
	return nil, nsec3Params{}, nsecLookupNone
}

// matchHashLocked finds the entry whose ownerHash equals H(name).
// Caller holds i.mu in any mode.
func (i *nsec3Index) matchHashLocked(z *nsec3ZoneIndex, name wire.Name, now time.Time) (nsec3Entry, bool) {
	want := nsec3HashOf(name, z.params)
	if want == nil {
		return nsec3Entry{}, false
	}
	idx, found := slices.BinarySearchFunc(z.entries, want,
		func(e nsec3Entry, target []byte) int { return bytes.Compare(e.ownerHash, target) })
	if !found {
		return nsec3Entry{}, false
	}
	e := z.entries[idx]
	if !e.expiresAt.After(now) {
		return nsec3Entry{}, false
	}
	return e, true
}

// coverHashLocked finds the entry whose (ownerHash, nextHash)
// interval covers H(name). Returns false if the candidate is
// expired OR has the opt-out flag set (RFC 8198 §5.6: an opt-out
// NSEC3 cannot prove non-existence of an arbitrary name).
func (i *nsec3Index) coverHashLocked(z *nsec3ZoneIndex, name wire.Name, now time.Time, denyOptOut bool) (nsec3Entry, bool) {
	target := nsec3HashOf(name, z.params)
	if target == nil {
		return nsec3Entry{}, false
	}
	for _, e := range z.entries {
		if !e.expiresAt.After(now) {
			continue
		}
		if denyOptOut && e.optOut {
			continue
		}
		if validatorbb.HashIntervalContains(e.ownerHash, e.nextHash, target) {
			return e, true
		}
	}
	return nsec3Entry{}, false
}

// closestEncloserProofLocked walks q's ancestor chain looking for
// the deepest one whose hash matches a cached NSEC3 (the "closest
// encloser"). It then verifies (a) the next-closer name's hash is
// covered by a cached NSEC3 with no opt-out, and (b) the wildcard
// at the closest encloser is covered by a cached NSEC3 with no
// opt-out. All three proofs together synthesize NXDOMAIN.
func (i *nsec3Index) closestEncloserProofLocked(z *nsec3ZoneIndex, q wire.Name, now time.Time) ([]nsec3Entry, bool) {
	// Walk q upward looking for the longest ancestor with a matching
	// NSEC3. The encloser must be at-or-below the zone apex (the
	// zone apex itself always matches if it's in the index).
	cur := q
	for {
		matchEntry, matched := i.matchHashLocked(z, cur, now)
		if matched {
			// closest encloser found at cur. Compute next_closer:
			// the name one label longer than cur, on the path to q.
			nextCloser := oneLabelLonger(q, cur)
			if !nextCloser.IsValid() {
				return nil, false
			}
			ncEntry, ncOK := i.coverHashLocked(z, nextCloser, now, true)
			if !ncOK {
				return nil, false
			}
			wildcard := wildcardAt(cur)
			if !wildcard.IsValid() {
				return nil, false
			}
			wcEntry, wcOK := i.coverHashLocked(z, wildcard, now, true)
			if !wcOK {
				return nil, false
			}
			return []nsec3Entry{matchEntry, ncEntry, wcEntry}, true
		}
		p, ok := cur.Parent()
		if !ok || cur.Equal(p) {
			return nil, false
		}
		cur = p
	}
}

// nsec3HashOf computes IH(salt, name, iterations) per RFC 5155 §5.1
// — H(x || salt) iterated `iterations` extra times after the
// initial round. Mirrors dnssec/validator's nsec3Hash; duplicated
// here to avoid importing the validator into the recursive
// package.
func nsec3HashOf(name wire.Name, p nsec3Params) []byte {
	if p.alg != nsec3HashSHA1 || p.iterations > maxNSEC3Iterations {
		return nil
	}
	buf := name.AppendWire(nil)
	buf = append(buf, p.salt...)
	h := sha1.Sum(buf) //nolint:gosec
	for range p.iterations {
		next := make([]byte, 0, len(h)+len(p.salt))
		next = append(next, h[:]...)
		next = append(next, p.salt...)
		h = sha1.Sum(next) //nolint:gosec
	}
	return h[:]
}

// oneLabelLonger returns the name that is one label longer than
// encloser, on the path from encloser toward q. Used to build the
// next-closer name in the closest-encloser proof.
func oneLabelLonger(q, encloser wire.Name) wire.Name {
	encLabels := encloser.NumLabels()
	n := q
	for n.NumLabels() > encLabels+1 {
		p, ok := n.Parent()
		if !ok || n.Equal(p) {
			return wire.Name{}
		}
		n = p
	}
	if n.NumLabels() != encLabels+1 {
		return wire.Name{}
	}
	return n
}

// wildcardAt returns the wildcard name *.encloser. Used in the
// wildcard-coverage half of the closest-encloser proof.
func wildcardAt(encloser wire.Name) wire.Name {
	wc, err := wire.ParseName("*." + encloser.String())
	if err != nil {
		return wire.Name{}
	}
	return wc
}

// extractValidatedNSEC3s picks NSEC3 records (and the SOA-zone
// apex they're rooted at, plus the NSEC3PARAM telling us the zone's
// hash params) out of the validated authority section. Callers
// guarantee resp was DNSSEC-validated before invoking.
func extractValidatedNSEC3s(authority []wire.Record, now time.Time) (zoneApex wire.Name, params nsec3Params, entries []nsec3Entry) {
	for _, r := range authority {
		if r.Type() == rrtype.SOA {
			zoneApex = r.Name()
			break
		}
	}
	if !zoneApex.IsValid() {
		return wire.Name{}, nsec3Params{}, nil
	}
	// The NSEC3 records themselves carry the params; pick from the
	// first one and verify the rest agree (a mismatch is a protocol
	// violation; we drop the entire batch in that case).
	for _, r := range authority {
		if r.Type() != rrtype.NSEC3 {
			continue
		}
		n3, ok := wire.RDataAs[rdata.NSEC3](r)
		if !ok {
			continue
		}
		p := nsec3Params{
			alg:        n3.HashAlgorithm(),
			iterations: n3.Iterations(),
			salt:       append([]byte(nil), n3.Salt()...),
		}
		if len(entries) == 0 {
			params = p
		} else if !params.equal(p) {
			return wire.Name{}, nsec3Params{}, nil
		}
		ownerHash, err := nsec3OwnerHashFromName(r.Name())
		if err != nil {
			continue
		}
		entries = append(entries, nsec3Entry{
			ownerHash: ownerHash,
			nextHash:  append([]byte(nil), n3.NextHashedOwner()...),
			types:     n3.Types(),
			optOut:    n3.Flags()&0x01 != 0,
			expiresAt: now.Add(r.TTL()),
		})
	}
	return zoneApex, params, entries
}

// nsec3OwnerHashFromName decodes the leftmost label of an NSEC3
// owner name from base32hex into the raw hash bytes.
func nsec3OwnerHashFromName(owner wire.Name) ([]byte, error) {
	for l := range owner.Labels() {
		s := string(l)
		// Uppercase as base32hex is case-insensitive but the
		// validatorbb decoder expects upper.
		up := make([]byte, len(s))
		for i := 0; i < len(s); i++ {
			c := s[i]
			if c >= 'a' && c <= 'z' {
				c -= 32
			}
			up[i] = c
		}
		return validatorbb.Base32HexDecode(string(up))
	}
	return nil, nil
}

// synthesiseFromNSEC3 consults the aggressive NSEC3 index and, if
// a §5.3/§5.4 proof can be assembled, returns a synthesised Entry.
// Returns (zero, false) when aggressive use is disabled, no
// matching zone is in the index, or no usable proof exists.
func (r *Recursive) synthesiseFromNSEC3(name wire.Name, t rrtype.Type) (Entry, bool) {
	if !r.aggressiveNSEC || r.nsec3Idx == nil {
		return Entry{}, false
	}
	now := time.Now()

	// Walk name's ancestors looking for a zone apex we have NSEC3
	// records for. The deepest match wins (a zone may delegate to a
	// child that's also NSEC3-signed; we want the more specific).
	var zone wire.Name
	r.nsec3Idx.mu.RLock()
	for cur := name; ; {
		if _, ok := r.nsec3Idx.zones[nameKey(cur)]; ok {
			zone = cur
			break
		}
		p, ok := cur.Parent()
		if !ok || cur.Equal(p) {
			break
		}
		cur = p
	}
	r.nsec3Idx.mu.RUnlock()
	if !zone.IsValid() {
		return Entry{}, false
	}

	entries, _, kind := r.nsec3Idx.Lookup(zone, name, t, now)
	if kind == nsecLookupNone {
		return Entry{}, false
	}

	// The synthesised authority carries the supporting NSEC3
	// records re-encoded with the proof's parameters and a fresh
	// remaining-lifetime TTL. The owner-name reconstruction uses
	// base32hex of the ownerHash + the zone apex.
	zoneAuth := r.nsec3Idx.zones[nameKey(zone)]
	authority := make([]wire.Record, 0, len(entries))
	for _, e := range entries {
		ownerName := nsec3OwnerName(e.ownerHash, zone)
		ttl := time.Until(e.expiresAt)
		if ttl <= 0 {
			return Entry{}, false
		}
		flags := uint8(0)
		if e.optOut {
			flags = 0x01
		}
		// salt and nextHash come from previously-validated NSEC3
		// records whose own decoder enforced the 255-byte cap, so
		// NewNSEC3 cannot fail here in practice — surface the error
		// loudly anyway so a future change that loosens the input
		// gates fails fast.
		n3, err := rdata.NewNSEC3(zoneAuth.params.alg, flags, zoneAuth.params.iterations,
			zoneAuth.params.salt, e.nextHash, e.types)
		if err != nil {
			return Entry{}, false
		}
		authority = append(authority, wire.NewRecord(ownerName, ttl, n3))
	}
	rcode := wire.RCODENXDomain
	if kind == nsecLookupNoData {
		rcode = wire.RCODENoError
	}
	earliest := entries[0].expiresAt
	for _, e := range entries[1:] {
		if e.expiresAt.Before(earliest) {
			earliest = e.expiresAt
		}
	}
	return Entry{
		authority: authority,
		rcode:     rcode,
		ad:        true,
		expiresAt: earliest,
	}, true
}

// nsec3OwnerName reconstructs an NSEC3 owner-name from the raw
// hash bytes and the zone apex.
func nsec3OwnerName(ownerHash []byte, zone wire.Name) wire.Name {
	label := validatorbb.Base32HexEncode(ownerHash)
	n, err := wire.ParseName(label + "." + zone.String())
	if err != nil {
		return wire.Name{}
	}
	return n
}
