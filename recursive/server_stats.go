package recursive

import (
	"net/netip"
	"sort"
	"sync"
	"time"
)

// ServerStats tracks per-upstream-server performance: smoothed RTT and a
// running failure count. The recursive resolver consults the store to rank
// candidate servers before each query, preferring fast-and-healthy servers.
//
// Implementations MUST be safe for concurrent use; the in-memory default
// is.
type ServerStats interface {
	Record(server netip.AddrPort, rtt time.Duration, ok bool)
	Score(server netip.AddrPort) Score
}

// Score summarises a server's current ranking inputs. Higher RTT or
// FailureStreak makes a server worse.
type Score struct {
	RTT           time.Duration
	FailureStreak int
}

// maxMemoryStatEntries caps the number of distinct upstream servers
// the in-memory ServerStats will track. Without a cap an open
// recursive resolver accumulates one entry per authoritative server
// it has ever consulted, and an attacker who controls an
// adversarial zone can fan that out arbitrarily by publishing many
// out-of-bailiwick NS records, since each new NS adds a new entry
// and the map never shrinks. 16384 entries is generous for any
// real Internet workload (~1.5 MB at ~96 bytes/entry) and small
// enough that a single eviction sweep stays well under a
// millisecond. Callers needing different sizing can supply their
// own ServerStats implementation via [WithStats].
const maxMemoryStatEntries = 16384

// memoryStatsEvictBatch is the number of stalest entries discarded
// in one sweep when the cap is reached. Batching amortises the
// O(n) scan over many inserts so the average cost per Record call
// past the cap stays at O(n / batch).
const memoryStatsEvictBatch = 64

type memoryStats struct {
	mu sync.Mutex
	m  map[netip.AddrPort]*statEntry
}

type statEntry struct {
	rtt      time.Duration // smoothed
	streak   int
	lastUsed time.Time
}

// NewMemoryStats returns an empty in-memory ServerStats.
func NewMemoryStats() ServerStats {
	return &memoryStats{m: make(map[netip.AddrPort]*statEntry)}
}

func (s *memoryStats) Record(server netip.AddrPort, rtt time.Duration, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.m[server]
	if e == nil {
		if len(s.m) >= maxMemoryStatEntries {
			s.evictOldestLocked(memoryStatsEvictBatch)
		}
		e = &statEntry{}
		s.m[server] = e
	}
	if ok {
		e.streak = 0
		// Smoothed RTT à la TCP RTO: 7/8 old + 1/8 new.
		if e.rtt == 0 {
			e.rtt = rtt
		} else {
			e.rtt = (e.rtt*7 + rtt) / 8
		}
	} else {
		e.streak++
	}
	e.lastUsed = time.Now()
}

func (s *memoryStats) Score(server netip.AddrPort) Score {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.m[server]
	if e == nil {
		return Score{}
	}
	return Score{RTT: e.rtt, FailureStreak: e.streak}
}

// evictOldestLocked removes up to n entries with the oldest lastUsed
// timestamp. The caller MUST hold s.mu. n is clamped to len(s.m).
//
// Implementation is a single O(n) pass that collects the n oldest
// entries via a max-heap-style insertion sort over a small fixed
// slice — for n ≪ len(s.m) (the expected case) the constant factor
// beats a full sort and avoids allocating a sortable slice.
func (s *memoryStats) evictOldestLocked(n int) {
	if n <= 0 || len(s.m) == 0 {
		return
	}
	if n > len(s.m) {
		n = len(s.m)
	}

	type oldest struct {
		key netip.AddrPort
		t   time.Time
	}
	victims := make([]oldest, 0, n)
	for k, v := range s.m {
		if len(victims) < n {
			victims = append(victims, oldest{k, v.lastUsed})
			continue
		}
		// Find the youngest of the current victims and evict it
		// in favour of v if v is older.
		youngestIdx := 0
		for i := 1; i < len(victims); i++ {
			if victims[i].t.After(victims[youngestIdx].t) {
				youngestIdx = i
			}
		}
		if v.lastUsed.Before(victims[youngestIdx].t) {
			victims[youngestIdx] = oldest{k, v.lastUsed}
		}
	}
	for _, o := range victims {
		delete(s.m, o.key)
	}
}

// rankServers sorts a slice of servers by stats: lowest failure streak
// first, ties broken by lowest RTT (fresh servers with rtt=0 sort BEFORE
// servers with measured high RTT, since rtt=0 means "untested" and we
// want to give them a chance).
func rankServers(stats ServerStats, servers []netip.AddrPort) []netip.AddrPort {
	out := append([]netip.AddrPort(nil), servers...)
	sort.SliceStable(out, func(i, j int) bool {
		si := stats.Score(out[i])
		sj := stats.Score(out[j])
		if si.FailureStreak != sj.FailureStreak {
			return si.FailureStreak < sj.FailureStreak
		}
		// Untested (RTT==0) goes first to give new servers a chance.
		if si.RTT == 0 && sj.RTT != 0 {
			return true
		}
		if sj.RTT == 0 && si.RTT != 0 {
			return false
		}
		return si.RTT < sj.RTT
	})
	return out
}
