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

type memoryStats struct {
	mu sync.Mutex
	m  map[netip.AddrPort]*statEntry
}

type statEntry struct {
	rtt       time.Duration // smoothed
	streak    int
	lastUsed  time.Time
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
