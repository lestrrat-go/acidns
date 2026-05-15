// Package shardbucket is a tiny sharded keyspace primitive shared by
// the rate-limit and RRL middlewares. Each middleware owns its bucket
// payload type, its token-refill logic, and its eviction policy —
// this package only provides the maphash-based sharding + per-shard
// mutex + bucket map that the two would otherwise duplicate.
//
// Generic in V so each caller's bucket struct stays unexported.
package shardbucket

import (
	"hash/maphash"
	"sync"
)

// NumShards stripes the keyspace so a flood of distinct sources
// doesn't serialize through one mutex. Power of two for mask-based
// modulo.
const NumShards = 64

// Shard holds the mutex + bucket map for one stripe.
//
// Buckets is pointer-typed (map[string]*V) so the hot path —
// in-place refill / decrement on V — does not write the map per
// allow() / consume() call. The cost is one heap allocation per new
// key. Switching to map[string]V eliminates that allocation under
// spoofed-source flood at the cost of ~10–20 ns/op on the hot path;
// the hot path dominates legitimate traffic, so the pointer-typed
// shape is intentional. The benchmarks in BenchmarkRateLimit*HotKey
// / BenchmarkRRL*HotKey pin the tradeoff.
type Shard[V any] struct {
	Mu      sync.Mutex
	Buckets map[string]*V
}

// Pool is a NumShards-wide collection of Shard[V].
type Pool[V any] struct {
	seed   maphash.Seed
	shards [NumShards]*Shard[V]
}

// New returns an initialised Pool with every shard's bucket map ready
// for use.
func New[V any]() *Pool[V] {
	p := &Pool[V]{seed: maphash.MakeSeed()}
	for i := range p.shards {
		p.shards[i] = &Shard[V]{Buckets: make(map[string]*V)}
	}
	return p
}

// ShardFor returns the shard responsible for key. The hash is
// keyed by a fresh per-Pool seed (set in New) so an attacker cannot
// craft keys that collide into the same shard across processes.
func (p *Pool[V]) ShardFor(key string) *Shard[V] {
	h := maphash.String(p.seed, key)
	return p.shards[h&(NumShards-1)]
}

// Len returns the total number of buckets across every shard. Each
// shard's lock is taken in turn, so the result is a consistent
// per-shard snapshot but not a globally atomic count. Intended for
// metrics + tests.
func (p *Pool[V]) Len() int {
	total := 0
	for _, sh := range p.shards {
		sh.Mu.Lock()
		total += len(sh.Buckets)
		sh.Mu.Unlock()
	}
	return total
}

// PerShardCap derives a per-shard cap from a desired total cap,
// rounded up so the actual ceiling fluctuates near totalCap depending
// on how keys hash across shards. Returns 0 when totalCap is
// non-positive (caller treats 0 as "uncapped").
func PerShardCap(totalCap int) int {
	if totalCap <= 0 {
		return 0
	}
	return (totalCap + NumShards - 1) / NumShards
}
