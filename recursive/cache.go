package recursive

import (
	"sync"
	"time"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// Cache stores authoritative response components keyed by (name, type) so a
// recursive resolver can satisfy repeated queries from memory.
//
// Implementations MUST be safe for concurrent use.
type Cache interface {
	Get(name wire.Name, t rrtype.Type) (Entry, bool)
	Put(name wire.Name, t rrtype.Type, e Entry)
}

// Entry is the cached form of an authoritative result.
type Entry struct {
	Answer     []wire.Record
	Authority  []wire.Record
	Additional []wire.Record
	RCODE      wire.RCODE
	AA         bool
	AD         bool
	ExpiresAt  time.Time
}

// DefaultMemoryCacheSize is the default upper bound on the number of
// entries [MemoryCache] retains; new inserts past the bound trigger
// eviction of expired entries first, then of the entry closest to its
// expiry. The value is conservative enough that a busy stub resolver
// won't churn but small enough that the cache cannot grow without
// bound under hostile traffic.
const DefaultMemoryCacheSize = 10000

// MemoryCache is the default in-memory Cache. Its size is bounded by
// [MemoryCacheOption] (default [DefaultMemoryCacheSize]); past that
// limit, [Put] evicts expired entries first and then the entry whose
// expiry is soonest.
type MemoryCache struct {
	mu      sync.RWMutex
	entries map[string]Entry
	maxSize int
}

// MemoryCacheOption configures a [MemoryCache] at construction.
type MemoryCacheOption interface{ applyMemoryCache(*memoryCacheConfig) }

type memoryCacheOptionFunc func(*memoryCacheConfig)

func (f memoryCacheOptionFunc) applyMemoryCache(c *memoryCacheConfig) { f(c) }

type memoryCacheConfig struct {
	maxSize int
}

// WithMemoryCacheSize sets the upper bound on entry count. A
// non-positive value disables the cap (legacy behaviour).
func WithMemoryCacheSize(n int) MemoryCacheOption {
	return memoryCacheOptionFunc(func(c *memoryCacheConfig) { c.maxSize = n })
}

// NewMemoryCache returns an empty MemoryCache. With no options the
// cache is bounded at [DefaultMemoryCacheSize].
func NewMemoryCache(opts ...MemoryCacheOption) *MemoryCache {
	c := memoryCacheConfig{maxSize: DefaultMemoryCacheSize}
	for _, o := range opts {
		o.applyMemoryCache(&c)
	}
	return &MemoryCache{entries: make(map[string]Entry), maxSize: c.maxSize}
}

func (c *MemoryCache) Get(name wire.Name, t rrtype.Type) (Entry, bool) {
	k := key(name, t)
	c.mu.RLock()
	e, ok := c.entries[k]
	c.mu.RUnlock()
	if !ok {
		return Entry{}, false
	}
	if time.Now().After(e.ExpiresAt) {
		c.mu.Lock()
		delete(c.entries, k)
		c.mu.Unlock()
		return Entry{}, false
	}
	return e, true
}

func (c *MemoryCache) Put(name wire.Name, t rrtype.Type, e Entry) {
	k := key(name, t)
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, replacing := c.entries[k]; !replacing && c.maxSize > 0 && len(c.entries) >= c.maxSize {
		c.evictLocked(time.Now())
	}
	c.entries[k] = e
}

// evictLocked frees space in the entry map. Two passes: drop expired
// entries first; if still at the cap, drop the entry whose expiry is
// soonest (an approximate-LRU keyed by remaining TTL). Caller holds
// c.mu in write mode.
func (c *MemoryCache) evictLocked(now time.Time) {
	for k, e := range c.entries {
		if !e.ExpiresAt.After(now) {
			delete(c.entries, k)
		}
	}
	if len(c.entries) < c.maxSize {
		return
	}
	var soonestKey string
	var soonestTime time.Time
	first := true
	for k, e := range c.entries {
		if first || e.ExpiresAt.Before(soonestTime) {
			soonestKey = k
			soonestTime = e.ExpiresAt
			first = false
		}
	}
	delete(c.entries, soonestKey)
}

// Len reports the number of entries currently held. Intended for tests
// and observability hooks; not part of the [Cache] interface.
func (c *MemoryCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

func key(n wire.Name, t rrtype.Type) string {
	return string(n.AppendWire(nil)) + "|" + t.String()
}

// minTTL returns the smallest TTL across the supplied record sets, or the
// provided floor if all sets are empty.
func minTTL(floor time.Duration, sets ...[]wire.Record) time.Duration {
	smallest := time.Duration(-1)
	for _, set := range sets {
		for _, r := range set {
			if smallest < 0 || r.TTL() < smallest {
				smallest = r.TTL()
			}
		}
	}
	if smallest < 0 {
		return floor
	}
	return smallest
}
