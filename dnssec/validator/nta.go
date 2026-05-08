package validator

import (
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/acidns/wire"
)

// DefaultNTATTL is the lifetime applied by [NTAStore.Add] when ttl <= 0.
// RFC 7646 §3 recommends a default of no more than 24 hours so a forgotten
// NTA cannot become a permanent validation hole.
const DefaultNTATTL = 24 * time.Hour

// MaxNTATTL is the upper bound clamped by [NTAStore.Add]. RFC 7646 §3
// caps NTAs at one week — operators that need a longer suppression must
// renew the entry explicitly so the decision is revisited.
const MaxNTATTL = 7 * 24 * time.Hour

// NTAStore is a runtime-mutable registry of Negative Trust Anchors. An
// owner name added to the store causes the validator to bypass validation
// for that name and all of its descendants and return Result Indeterminate
// (with NTAMatch=true).
//
// Each entry carries an expiry time; expired entries no longer match.
// RFC 7646 §3 requires NTAs to expire so they cannot silently outlive
// the operational issue that prompted them.
//
// Safe for concurrent use.
type NTAStore struct {
	mu  sync.RWMutex
	set map[string]ntaEntry
	now func() time.Time
}

type ntaEntry struct {
	name      wire.Name
	expiresAt time.Time
}

// NewNTAStore constructs an NTA registry pre-loaded with the given names.
// Initial names are inserted with [DefaultNTATTL] expiry.
func NewNTAStore(initial ...wire.Name) *NTAStore {
	s := &NTAStore{set: make(map[string]ntaEntry), now: time.Now}
	for _, n := range initial {
		s.Add(n, DefaultNTATTL)
	}
	return s
}

// Add registers an NTA expiring after ttl. A non-positive ttl is replaced
// by [DefaultNTATTL]; a ttl exceeding [MaxNTATTL] is clamped down. Adding
// a name that already has an entry refreshes the expiry. Returns true if
// the entry is new (not just renewed).
func (s *NTAStore) Add(n wire.Name, ttl time.Duration) bool {
	if !n.IsValid() {
		return false
	}
	if ttl <= 0 {
		ttl = DefaultNTATTL
	}
	if ttl > MaxNTATTL {
		ttl = MaxNTATTL
	}
	k := strings.ToLower(n.String())
	s.mu.Lock()
	defer s.mu.Unlock()
	_, existed := s.set[k]
	s.set[k] = ntaEntry{name: n, expiresAt: s.now().Add(ttl)}
	return !existed
}

// Remove deletes an NTA. Returns true if an entry existed (whether or not
// it had already expired).
func (s *NTAStore) Remove(n wire.Name) bool {
	if !n.IsValid() {
		return false
	}
	k := strings.ToLower(n.String())
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.set[k]; !ok {
		return false
	}
	delete(s.set, k)
	return true
}

// Names returns a snapshot of currently-active (unexpired) NTAs.
func (s *NTAStore) Names() []wire.Name {
	now := s.now()
	s.mu.RLock()
	hasExpired := s.hasExpiredLocked(now)
	s.mu.RUnlock()
	if hasExpired {
		s.mu.Lock()
		s.sweepExpiredLocked(now)
		s.mu.Unlock()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]wire.Name, 0, len(s.set))
	for _, e := range s.set {
		if e.expiresAt.After(now) {
			out = append(out, e.name)
		}
	}
	return out
}

// Covers reports whether n falls under any active NTA. Expired entries
// are ignored (and lazily evicted). The empty store always reports false.
//
// The fast path holds only an RLock — under heavy DNSSEC validation
// traffic this lets concurrent Covers callers run in parallel. The
// store upgrades to a write lock only when an expired entry is observed
// during the scan, which is rare in steady state.
func (s *NTAStore) Covers(n wire.Name) bool {
	if !n.IsValid() {
		return false
	}
	now := s.now()
	s.mu.RLock()
	if len(s.set) == 0 {
		s.mu.RUnlock()
		return false
	}
	matched, sawExpired := s.coverScanLocked(n, now)
	s.mu.RUnlock()
	if sawExpired {
		s.mu.Lock()
		s.sweepExpiredLocked(now)
		s.mu.Unlock()
	}
	return matched
}

// coverScanLocked walks n's ancestor chain looking for an active match.
// Returns (matched, sawExpired); sawExpired triggers a lazy sweep
// after the read lock is released. Caller holds s.mu in any mode.
func (s *NTAStore) coverScanLocked(n wire.Name, now time.Time) (bool, bool) {
	matched := false
	sawExpired := false
	cur := n
	for {
		k := strings.ToLower(cur.String())
		if e, ok := s.set[k]; ok {
			if e.expiresAt.After(now) {
				matched = true
				break
			}
			sawExpired = true
		}
		parent, hasParent := cur.Parent()
		if !hasParent || cur.Equal(parent) {
			break
		}
		cur = parent
	}
	if !sawExpired {
		// Quick check for any other expired entries; bound work to a
		// few entries so the read path stays cheap.
		i := 0
		for _, e := range s.set {
			if !e.expiresAt.After(now) {
				sawExpired = true
				break
			}
			i++
			if i >= 8 {
				break
			}
		}
	}
	return matched, sawExpired
}

// hasExpiredLocked reports whether any entry has expired by now. Caller
// holds s.mu in any mode.
func (s *NTAStore) hasExpiredLocked(now time.Time) bool {
	for _, e := range s.set {
		if !e.expiresAt.After(now) {
			return true
		}
	}
	return false
}

// sweepExpiredLocked removes entries whose expiry is at or before now.
// Caller holds s.mu in write mode.
func (s *NTAStore) sweepExpiredLocked(now time.Time) {
	for k, e := range s.set {
		if !e.expiresAt.After(now) {
			delete(s.set, k)
		}
	}
}
