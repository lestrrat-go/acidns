// Package validator wires the dnssec verification primitives into a
// chain-of-trust validator with first-class Negative Trust Anchor (NTA)
// support, per the project's DNSSEC stance: NTAs are an operational
// requirement, not a bolt-on (cf. the May-2025 .de TLD outage).
//
// The validator does NOT yet implement a recursive chain walker — that
// requires a Resolver hook to fetch DNSKEY/DS records on demand and is a
// separate concern. What this package supplies:
//
//   - Result: Secure / Insecure / Bogus / Indeterminate (RFC 4035 §4.3).
//   - NTAStore: runtime-mutable NTA registry, safe for concurrent use.
//   - Validator: validates a pre-resolved authentication chain (a parent
//     DS, the matching zone DNSKEY set, and the RRSIG over the answer).
//
// A future Resolver-aware walker can compose Validator with chain
// retrieval; the API shape (and especially NTA bypass) does not change.
package validator

import (
	"strings"
	"sync"

	"github.com/lestrrat-go/acidns/wire"
)

// NTAStore is a runtime-mutable registry of Negative Trust Anchors. An
// owner name added to the store causes the validator to bypass validation
// for that name and all of its descendants and return Result Indeterminate
// (with NTAMatch=true).
//
// Safe for concurrent use.
type NTAStore struct {
	mu  sync.RWMutex
	set map[string]struct{}
}

// NewNTAStore constructs an empty NTA registry pre-loaded with the given
// names.
func NewNTAStore(initial ...wire.Name) *NTAStore {
	s := &NTAStore{set: make(map[string]struct{})}
	for _, n := range initial {
		s.Add(n)
	}
	return s
}

// Add registers an NTA. Returns true if the entry was newly added.
func (s *NTAStore) Add(n wire.Name) bool {
	if !n.IsValid() {
		return false
	}
	k := strings.ToLower(n.String())
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.set[k]; ok {
		return false
	}
	s.set[k] = struct{}{}
	return true
}

// Remove deletes an NTA. Returns true if an entry existed.
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

// Names returns a snapshot of the configured NTAs.
func (s *NTAStore) Names() []wire.Name {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]wire.Name, 0, len(s.set))
	for k := range s.set {
		n, err := wire.ParseName(k)
		if err == nil {
			out = append(out, n)
		}
	}
	return out
}

// Covers reports whether n falls under any registered NTA. The empty
// store always reports false.
func (s *NTAStore) Covers(n wire.Name) bool {
	if !n.IsValid() {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.set) == 0 {
		return false
	}
	cur := n
	for {
		k := strings.ToLower(cur.String())
		if _, ok := s.set[k]; ok {
			return true
		}
		parent, hasParent := cur.Parent()
		if !hasParent || cur.Equal(parent) {
			return false
		}
		cur = parent
	}
}
