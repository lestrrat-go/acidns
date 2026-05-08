package tsig

import (
	"encoding/hex"
	"strconv"
	"sync"
	"time"

	"github.com/lestrrat-go/acidns/wire"
)

// ReplayCache deduplicates verified TSIG-signed messages so a captured
// envelope cannot be re-played within the fudge window. RFC 8945 §5.2.3
// leaves replay defence to the application; callers handling UPDATE,
// NOTIFY, or any other side-effecting opcode that arrives over a
// TSIG-protected channel are expected to consult one before treating a
// verified message as fresh.
//
// The recommended usage is to call Seen inside an authoritative
// server's [authoritative.UpdatePolicy] after VerifyMAC succeeds:
//
//	cache := tsig.NewMemoryReplayCache()
//	policy := func(ctx context.Context, w acidns.ResponseWriter, q wire.Message) bool {
//	    raw := acidns.RawRequest(ctx)
//	    _, mac, signedAt, err := tsig.VerifyMAC(raw, key, time.Now(), 5*time.Minute)
//	    if err != nil { return false }
//	    if cache.Seen(key.Name(), signedAt, mac) { return false } // replay
//	    return true
//	}
//
// Implementations MUST be safe for concurrent use.
type ReplayCache interface {
	// Seen records the (keyName, signedAt, mac) tuple and reports
	// whether the tuple was already present. A true return means the
	// message is a replay of one already verified within the cache's
	// retention window and SHOULD be rejected.
	Seen(keyName wire.Name, signedAt time.Time, mac []byte) bool
}

// DefaultReplayWindow matches RFC 8945's recommended 5-minute fudge.
const DefaultReplayWindow = 5 * time.Minute

// DefaultReplayCacheSize bounds the in-memory cache so a flood of
// distinct signatures cannot exhaust memory. The default holds well
// over a thousand UPDATEs per second within a five-minute window.
const DefaultReplayCacheSize = 16384

// ReplayCacheOption configures a [MemoryReplayCache] at construction.
type ReplayCacheOption interface{ applyReplayCache(*replayCacheConfig) }

type replayCacheOptionFunc func(*replayCacheConfig)

func (f replayCacheOptionFunc) applyReplayCache(c *replayCacheConfig) { f(c) }

type replayCacheConfig struct {
	size   int
	window time.Duration
	now    func() time.Time
}

// WithReplayWindow sets the retention window. Entries older than the
// window are evicted and the same signature can re-enter the cache
// after that interval. Set this to match the fudge passed to
// [Verify]; the receiver only accepts signatures whose timestamp is
// within fudge of "now," so an entry older than fudge cannot be a
// live replay anyway.
func WithReplayWindow(d time.Duration) ReplayCacheOption {
	return replayCacheOptionFunc(func(c *replayCacheConfig) { c.window = d })
}

// WithReplayCacheSize sets the maximum number of distinct verified
// signatures retained simultaneously. A non-positive value disables
// the size cap (eviction then runs purely on age).
func WithReplayCacheSize(n int) ReplayCacheOption {
	return replayCacheOptionFunc(func(c *replayCacheConfig) { c.size = n })
}

// WithReplayClock injects a clock for tests. Defaults to time.Now.
func WithReplayClock(now func() time.Time) ReplayCacheOption {
	return replayCacheOptionFunc(func(c *replayCacheConfig) { c.now = now })
}

// NewMemoryReplayCache returns an in-memory [ReplayCache] suitable for
// the typical authoritative-or-recursive-server deployment. The cache
// is sharded internally only by the encoded key — a single mutex
// protects the map; for production volumes well past 10 K signatures/s
// a sharded implementation may be preferable.
func NewMemoryReplayCache(opts ...ReplayCacheOption) *MemoryReplayCache {
	c := replayCacheConfig{
		size:   DefaultReplayCacheSize,
		window: DefaultReplayWindow,
		now:    time.Now,
	}
	for _, o := range opts {
		o.applyReplayCache(&c)
	}
	return &MemoryReplayCache{
		size:   c.size,
		window: c.window,
		now:    c.now,
		seen:   make(map[string]time.Time),
	}
}

// MemoryReplayCache is the default in-memory [ReplayCache]. The zero
// value is unusable; construct via [NewMemoryReplayCache].
type MemoryReplayCache struct {
	size   int
	window time.Duration
	now    func() time.Time

	mu   sync.Mutex
	seen map[string]time.Time
}

// Seen records a verified signature and reports replay status.
func (c *MemoryReplayCache) Seen(keyName wire.Name, signedAt time.Time, mac []byte) bool {
	k := replayKey(keyName, signedAt, mac)
	now := c.now()

	c.mu.Lock()
	defer c.mu.Unlock()

	c.evictExpiredLocked(now)

	if t, exists := c.seen[k]; exists {
		// Refresh the timestamp so a steadily replayed signature
		// continues to be flagged for the full window without
		// expiring out from under the second observation.
		_ = t
		c.seen[k] = now
		return true
	}

	if c.size > 0 && len(c.seen) >= c.size {
		c.evictOldestLocked()
	}
	c.seen[k] = now
	return false
}

// Len reports the current number of cached signatures. Useful for
// tests and observability hooks.
func (c *MemoryReplayCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen)
}

func (c *MemoryReplayCache) evictExpiredLocked(now time.Time) {
	cutoff := now.Add(-c.window)
	for k, t := range c.seen {
		if t.Before(cutoff) {
			delete(c.seen, k)
		}
	}
}

func (c *MemoryReplayCache) evictOldestLocked() {
	var oldestKey string
	var oldestT time.Time
	first := true
	for k, t := range c.seen {
		if first || t.Before(oldestT) {
			oldestKey = k
			oldestT = t
			first = false
		}
	}
	delete(c.seen, oldestKey)
}

// replayKey produces a unique identifier for the (key, time, MAC)
// tuple. The key is built deterministically from the canonical wire
// form of the name, the unix timestamp, and the hex-encoded MAC; that
// shape keeps it printable for tests without leaking the secret
// material that produced the MAC.
func replayKey(keyName wire.Name, signedAt time.Time, mac []byte) string {
	var b []byte
	b = keyName.AppendWire(b)
	b = append(b, '|')
	b = strconv.AppendInt(b, signedAt.Unix(), 10)
	b = append(b, '|')
	b = append(b, hex.EncodeToString(mac)...)
	return string(b)
}
