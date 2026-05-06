package recursive

import (
	"sync"
	"time"

	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
)

// Cache stores authoritative response components keyed by (name, type) so a
// recursive resolver can satisfy repeated queries from memory.
//
// Implementations MUST be safe for concurrent use.
type Cache interface {
	Get(name dnsname.Name, t rrtype.Type) (Entry, bool)
	Put(name dnsname.Name, t rrtype.Type, e Entry)
}

// Entry is the cached form of an authoritative result.
type Entry struct {
	Answer     []dnsmsg.Record
	Authority  []dnsmsg.Record
	Additional []dnsmsg.Record
	RCODE      dnsmsg.RCODE
	AA         bool
	ExpiresAt  time.Time
}

// MemoryCache is the default in-memory Cache.
type MemoryCache struct {
	mu      sync.RWMutex
	entries map[string]Entry
}

// NewMemoryCache returns an empty MemoryCache.
func NewMemoryCache() *MemoryCache {
	return &MemoryCache{entries: make(map[string]Entry)}
}

func (c *MemoryCache) Get(name dnsname.Name, t rrtype.Type) (Entry, bool) {
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

func (c *MemoryCache) Put(name dnsname.Name, t rrtype.Type, e Entry) {
	c.mu.Lock()
	c.entries[key(name, t)] = e
	c.mu.Unlock()
}

func key(n dnsname.Name, t rrtype.Type) string {
	return string(n.AppendWire(nil)) + "|" + t.String()
}

// minTTL returns the smallest TTL across the supplied record sets, or the
// provided floor if all sets are empty.
func minTTL(floor time.Duration, sets ...[]dnsmsg.Record) time.Duration {
	min := time.Duration(-1)
	for _, set := range sets {
		for _, r := range set {
			if min < 0 || r.TTL() < min {
				min = r.TTL()
			}
		}
	}
	if min < 0 {
		return floor
	}
	return min
}
