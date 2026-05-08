package forward

import (
	"container/list"
	"sync"
	"time"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// entry is one cached forwarder result. The records are stored with
// their as-received TTLs; serve-time TTLs are derived by subtracting
// the elapsed since insertedAt.
type entry struct {
	answers    []wire.Record
	authority  []wire.Record
	additional []wire.Record
	rcode      wire.RCODE
	ad         bool
	insertedAt time.Time
	expiresAt  time.Time
}

type cacheKey struct {
	name  string
	qtype rrtype.Type
	class rrtype.Class
}

// cache is a fixed-size LRU. nil-receiver methods are no-ops so a
// zero capacity cleanly disables caching.
type cache struct {
	mu  sync.Mutex
	cap int
	lru *list.List
	m   map[cacheKey]*list.Element
}

func newCache(capacity int) *cache {
	if capacity <= 0 {
		return nil
	}
	return &cache{
		cap: capacity,
		lru: list.New(),
		m:   make(map[cacheKey]*list.Element, capacity),
	}
}

type cacheItem struct {
	key cacheKey
	val entry
}

func (c *cache) get(name wire.Name, qtype rrtype.Type, class rrtype.Class, now time.Time) (entry, bool) {
	if c == nil {
		return entry{}, false
	}
	k := makeKey(name, qtype, class)
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.m[k]
	if !ok {
		return entry{}, false
	}
	it, _ := el.Value.(*cacheItem)
	if !now.Before(it.val.expiresAt) {
		c.lru.Remove(el)
		delete(c.m, k)
		return entry{}, false
	}
	c.lru.MoveToFront(el)
	return it.val, true
}

func (c *cache) put(name wire.Name, qtype rrtype.Type, class rrtype.Class, e entry) {
	if c == nil {
		return
	}
	k := makeKey(name, qtype, class)
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[k]; ok {
		if it, ok := el.Value.(*cacheItem); ok {
			it.val = e
		}
		c.lru.MoveToFront(el)
		return
	}
	el := c.lru.PushFront(&cacheItem{key: k, val: e})
	c.m[k] = el
	if c.lru.Len() > c.cap {
		oldest := c.lru.Back()
		if oldest != nil {
			c.lru.Remove(oldest)
			if it, ok := oldest.Value.(*cacheItem); ok {
				delete(c.m, it.key)
			}
		}
	}
}

func (c *cache) len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}

func makeKey(name wire.Name, qtype rrtype.Type, class rrtype.Class) cacheKey {
	return cacheKey{
		name:  string(name.AppendWire(nil)),
		qtype: qtype,
		class: class,
	}
}
