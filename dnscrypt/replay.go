package dnscrypt

import (
	"sync"
	"time"
)

// replayCache rejects re-presented (clientPK, nonce) tuples within a
// sliding window. The DNSCrypt v2 wire format binds the per-packet
// nonce only to AEAD authenticity, not to time — so a captured
// packet can be re-injected indefinitely and re-dispatched to the
// handler. Storing seen tuples for replayWindow gives stateless
// replay defence at modest cost.
//
// Implementation: a single map under sync.Mutex with opportunistic
// sweep. The mutex bounds throughput at "millions of small ops per
// CPU per second" which is well above plausible DNSCrypt query
// rates. Adopters that need higher rates should switch to a sharded
// or lock-free structure — but the API exposed by [seen] does not
// change.
type replayCache struct {
	mu      sync.Mutex
	entries map[[44]byte]time.Time
	window  time.Duration
	max     int
}

func newReplayCache(window time.Duration, maxEntries int) *replayCache {
	return &replayCache{
		entries: make(map[[44]byte]time.Time),
		window:  window,
		max:     maxEntries,
	}
}

// seen reports whether (clientPK, nonce) was already observed within
// the replay window relative to now. The first call for a given
// tuple records it and returns false; a second call within the
// window returns true. Calls outside the window record the new
// timestamp and return false.
func (c *replayCache) seen(clientPK [32]byte, nonce [12]byte, now time.Time) bool {
	var key [44]byte
	copy(key[:32], clientPK[:])
	copy(key[32:], nonce[:])

	c.mu.Lock()
	defer c.mu.Unlock()

	cutoff := now.Add(-c.window)
	if t, ok := c.entries[key]; ok {
		if t.After(cutoff) {
			return true
		}
		// Stale entry under the same key — overwrite below.
	}

	if len(c.entries) >= c.max {
		// Sweep expired entries first.
		for k, t := range c.entries {
			if !t.After(cutoff) {
				delete(c.entries, k)
			}
		}
		// If the cache is still full, evict the oldest entries until
		// we are back under max. Map iteration order is random so
		// this samples uniformly; for max=10k that's a one-time
		// O(n) cost at saturation, well below the cost of an
		// X25519+AEAD per packet.
		if len(c.entries) >= c.max {
			oldest := now
			var oldestKey [44]byte
			for k, t := range c.entries {
				if t.Before(oldest) {
					oldest = t
					oldestKey = k
				}
			}
			delete(c.entries, oldestKey)
		}
	}
	c.entries[key] = now
	return false
}
