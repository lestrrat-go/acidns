package recursive

import (
	"hash/maphash"
	"sync"
	"time"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// Cache stores authoritative response components keyed by
// (name, class, type) so a recursive resolver can satisfy repeated
// queries from memory. Class is part of the key so a CHAOS-class query
// cannot collide with the IN-class entry of the same name and type.
//
// Implementations MUST be safe for concurrent use.
type Cache interface {
	Get(name wire.Name, c rrtype.Class, t rrtype.Type) (Entry, bool)
	Put(name wire.Name, c rrtype.Class, t rrtype.Type, e Entry)
}

// Entry is the cached form of an authoritative result. Fields are
// unexported per the project's style rule that parsed-record
// carriers expose accessors rather than fields — a Cache
// implementation that forgets to clone Entry's slice fields cannot
// poison readers, and callers cannot mutate the returned value to
// shift its semantics (e.g. zeroing ExpiresAt would mark the entry
// expired). Construct via [NewEntryBuilder].
type Entry struct {
	answer     []wire.Record
	authority  []wire.Record
	additional []wire.Record
	rcode      wire.RCODE
	aa         bool
	ad         bool
	expiresAt  time.Time
}

// Answer returns the answer-section records.
func (e Entry) Answer() []wire.Record { return e.answer }

// Authority returns the authority-section records.
func (e Entry) Authority() []wire.Record { return e.authority }

// Additional returns the additional-section records.
func (e Entry) Additional() []wire.Record { return e.additional }

// RCODE returns the response code carried by the cached answer.
func (e Entry) RCODE() wire.RCODE { return e.rcode }

// AA reports whether the cached answer was returned by an
// authoritative server.
func (e Entry) AA() bool { return e.aa }

// AD reports whether the cached answer's authentic-data bit was set.
func (e Entry) AD() bool { return e.ad }

// ExpiresAt is the absolute time at which the cached entry should
// no longer be returned.
func (e Entry) ExpiresAt() time.Time { return e.expiresAt }

// EntryBuilder constructs an [Entry]. Like other builders in the
// codebase it is owned by a single goroutine; the returned Entry is
// immutable and may be shared.
type EntryBuilder struct{ e Entry }

// NewEntryBuilder returns a fresh EntryBuilder with the zero value.
func NewEntryBuilder() *EntryBuilder { return &EntryBuilder{} }

// Answer sets the answer-section records.
func (b *EntryBuilder) Answer(r []wire.Record) *EntryBuilder { b.e.answer = r; return b }

// Authority sets the authority-section records.
func (b *EntryBuilder) Authority(r []wire.Record) *EntryBuilder {
	b.e.authority = r
	return b
}

// Additional sets the additional-section records.
func (b *EntryBuilder) Additional(r []wire.Record) *EntryBuilder {
	b.e.additional = r
	return b
}

// RCODE sets the cached response code.
func (b *EntryBuilder) RCODE(c wire.RCODE) *EntryBuilder { b.e.rcode = c; return b }

// AA sets the authoritative-answer bit.
func (b *EntryBuilder) AA(v bool) *EntryBuilder { b.e.aa = v; return b }

// AD sets the authentic-data bit.
func (b *EntryBuilder) AD(v bool) *EntryBuilder { b.e.ad = v; return b }

// ExpiresAt sets the absolute expiry instant.
func (b *EntryBuilder) ExpiresAt(t time.Time) *EntryBuilder { b.e.expiresAt = t; return b }

// Build returns the constructed Entry. Currently infallible; the
// (Entry, error) shape matches the rest of the builder family in
// this module so future validation can be added without an API
// break.
func (b *EntryBuilder) Build() (Entry, error) { return b.e, nil }

// DefaultMemoryCacheSize is the default upper bound on the number of
// entries [MemoryCache] retains across all internal shards; new
// inserts past the bound trigger eviction of expired entries first,
// then of the entry closest to its expiry. The value is conservative
// enough that a busy stub resolver won't churn but small enough that
// the cache cannot grow without bound under hostile traffic.
const DefaultMemoryCacheSize = 10000

// DefaultMaxRecordsPerEntry caps how many records a single Entry may
// retain across its Answer/Authority/Additional slices. A hostile
// zone that returns thousands of records per response could otherwise
// inflate cache memory beyond the entry-count bound; the per-entry
// cap closes that gap.
const DefaultMaxRecordsPerEntry = 256

// numCacheShards stripes the entries map. Each shard has its own
// RWMutex, so cache reads/writes don't contend across unrelated keys.
// Power of two for mask-based modulo.
const numCacheShards = 64

// MemoryCache is the default in-memory Cache. Its size is bounded by
// [MemoryCacheOption] (default [DefaultMemoryCacheSize]); past that
// limit, [Put] evicts expired entries first and then the entry whose
// expiry is soonest, on a per-shard basis.
type MemoryCache struct {
	maxSize           int // per-shard cap (config / numCacheShards)
	maxRecordsPerEntr int
	seed              maphash.Seed
	shards            [numCacheShards]*memoryCacheShard
}

type memoryCacheShard struct {
	mu      sync.RWMutex
	entries map[string]Entry
}

// MemoryCacheOption configures a [MemoryCache] at construction.
type MemoryCacheOption interface{ applyMemoryCache(*memoryCacheConfig) }

type memoryCacheOptionFunc func(*memoryCacheConfig)

func (f memoryCacheOptionFunc) applyMemoryCache(c *memoryCacheConfig) { f(c) }

type memoryCacheConfig struct {
	maxSize           int
	maxRecordsPerEntr int
}

// WithMemoryCacheSize sets the upper bound on total entries across all
// shards. The cap is applied per-shard as ceil(n/64). A non-positive
// value disables the cap.
func WithMemoryCacheSize(n int) MemoryCacheOption {
	return memoryCacheOptionFunc(func(c *memoryCacheConfig) { c.maxSize = n })
}

// WithMemoryCacheMaxRecordsPerEntry caps how many records a single
// cached Entry may contain (sum of Answer + Authority + Additional).
// A non-positive value disables the cap; the default is
// [DefaultMaxRecordsPerEntry].
func WithMemoryCacheMaxRecordsPerEntry(n int) MemoryCacheOption {
	return memoryCacheOptionFunc(func(c *memoryCacheConfig) { c.maxRecordsPerEntr = n })
}

// NewMemoryCache returns an empty MemoryCache. With no options the
// cache is bounded at [DefaultMemoryCacheSize] entries and
// [DefaultMaxRecordsPerEntry] records per entry.
func NewMemoryCache(opts ...MemoryCacheOption) *MemoryCache {
	c := memoryCacheConfig{
		maxSize:           DefaultMemoryCacheSize,
		maxRecordsPerEntr: DefaultMaxRecordsPerEntry,
	}
	for _, o := range opts {
		o.applyMemoryCache(&c)
	}
	mc := &MemoryCache{
		maxRecordsPerEntr: c.maxRecordsPerEntr,
		seed:              maphash.MakeSeed(),
	}
	if c.maxSize > 0 {
		mc.maxSize = (c.maxSize + numCacheShards - 1) / numCacheShards
	}
	for i := range mc.shards {
		mc.shards[i] = &memoryCacheShard{entries: make(map[string]Entry)}
	}
	return mc
}

func (c *MemoryCache) shardFor(k string) *memoryCacheShard {
	h := maphash.String(c.seed, k)
	return c.shards[h&(numCacheShards-1)]
}

// Get returns the cached Entry for (name, class, type), or the zero
// value when the entry is missing or expired. The returned Entry's
// slice fields are freshly allocated copies of the cache's storage —
// caller code may mutate the returned slices without poisoning other
// readers. Records themselves are concrete value types and may be
// shared.
func (c *MemoryCache) Get(name wire.Name, cl rrtype.Class, t rrtype.Type) (Entry, bool) {
	k := key(name, cl, t)
	sh := c.shardFor(k)
	sh.mu.RLock()
	e, ok := sh.entries[k]
	sh.mu.RUnlock()
	if !ok {
		return Entry{}, false
	}
	if time.Now().After(e.expiresAt) {
		sh.mu.Lock()
		delete(sh.entries, k)
		sh.mu.Unlock()
		return Entry{}, false
	}
	return cloneEntry(e), true
}

// Put stores e in the cache. The slice fields of e are copied so a
// caller continuing to use its source slices after Put cannot
// retroactively corrupt the cache's view of the entry.
func (c *MemoryCache) Put(name wire.Name, cl rrtype.Class, t rrtype.Type, e Entry) {
	if c.maxRecordsPerEntr > 0 {
		e = capEntryRecords(e, c.maxRecordsPerEntr)
	}
	stored := cloneEntry(e)
	k := key(name, cl, t)
	sh := c.shardFor(k)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if _, replacing := sh.entries[k]; !replacing && c.maxSize > 0 && len(sh.entries) >= c.maxSize {
		c.evictLocked(sh, time.Now())
	}
	sh.entries[k] = stored
}

// cloneEntry returns a copy of e with each section slice freshly
// allocated. Records are value types and need no deep copy.
func cloneEntry(e Entry) Entry {
	return Entry{
		answer:     cloneRecords(e.answer),
		authority:  cloneRecords(e.authority),
		additional: cloneRecords(e.additional),
		rcode:      e.rcode,
		aa:         e.aa,
		ad:         e.ad,
		expiresAt:  e.expiresAt,
	}
}

func cloneRecords(s []wire.Record) []wire.Record {
	if len(s) == 0 {
		return nil
	}
	out := make([]wire.Record, len(s))
	copy(out, s)
	return out
}

// capEntryRecords trims an Entry's record slices so the sum across
// answer/authority/additional does not exceed limit. Trimming favours
// dropping additional first (least operationally important), then
// authority, then answer — keeping the answer path intact for as long
// as possible.
func capEntryRecords(e Entry, limit int) Entry {
	total := len(e.answer) + len(e.authority) + len(e.additional)
	if total <= limit {
		return e
	}
	trim := total - limit
	if n := len(e.additional); n > 0 {
		drop := min(n, trim)
		e.additional = e.additional[:n-drop]
		trim -= drop
	}
	if trim > 0 && len(e.authority) > 0 {
		n := len(e.authority)
		drop := min(n, trim)
		e.authority = e.authority[:n-drop]
		trim -= drop
	}
	if trim > 0 && len(e.answer) > 0 {
		n := len(e.answer)
		drop := min(n, trim)
		e.answer = e.answer[:n-drop]
	}
	return e
}

// evictLocked frees space in a shard. Two passes: drop expired
// entries first; if still at the per-shard cap, drop the entry whose
// expiry is soonest (an approximate-LRU keyed by remaining TTL).
// Caller holds sh.mu in write mode.
func (c *MemoryCache) evictLocked(sh *memoryCacheShard, now time.Time) {
	for k, e := range sh.entries {
		if !e.expiresAt.After(now) {
			delete(sh.entries, k)
		}
	}
	if len(sh.entries) < c.maxSize {
		return
	}
	var soonestKey string
	var soonestTime time.Time
	first := true
	for k, e := range sh.entries {
		if first || e.expiresAt.Before(soonestTime) {
			soonestKey = k
			soonestTime = e.expiresAt
			first = false
		}
	}
	delete(sh.entries, soonestKey)
}

// Len reports the total number of entries currently held across all
// shards. Intended for tests and observability hooks; not part of the
// [Cache] interface.
func (c *MemoryCache) Len() int {
	total := 0
	for _, sh := range c.shards {
		sh.mu.RLock()
		total += len(sh.entries)
		sh.mu.RUnlock()
	}
	return total
}

func key(n wire.Name, c rrtype.Class, t rrtype.Type) string {
	return string(n.AppendWire(nil)) + "|" + c.String() + "|" + t.String()
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
