package tsig

import (
	"encoding/hex"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/option/v3"
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
		switch o.Ident() {
		case identReplayWindow{}:
			c.window = option.MustGet[time.Duration](o)
		case identReplayCacheSize{}:
			c.size = option.MustGet[int](o)
		case identReplayClock{}:
			c.now = option.MustGet[func() time.Time](o)
		}
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

	mu        sync.Mutex
	seen      map[string]time.Time
	lastSweep time.Time
}

// ErrReplay is returned by [VerifyWithReplay] when the message's MAC
// has already been observed within the cache window.
var ErrReplay = errors.New("tsig: replay detected")

// VerifyWithReplay is the canonical "verify then check replay" wrapper.
// It first calls [VerifyMAC]; if that returns nil it consults cache for
// the (keyName, signedAt, mac) triple. A replay returns [ErrReplay].
//
// Using this wrapper instead of calling Verify and Seen separately
// avoids the easy-to-forget two-step pattern that leaves the receiver
// open to fudge-window replays. cache must be safe for concurrent use.
func VerifyWithReplay(msg []byte, key Key, cache ReplayCache, now time.Time, fudge time.Duration) ([]byte, []byte, time.Time, error) {
	body, mac, signed, err := VerifyMAC(msg, key, now, fudge)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	if cache != nil && cache.Seen(key.Name(), signed, mac) {
		return nil, nil, signed, ErrReplay
	}
	return body, mac, signed, nil
}

// Seen records a verified signature and reports replay status.
func (c *MemoryReplayCache) Seen(keyName wire.Name, signedAt time.Time, mac []byte) bool {
	k := replayKey(keyName, signedAt, mac)
	now := c.now()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Sweep expired entries only when (a) the cache is at least
	// half-full — so legitimate steady-state operation doesn't pay
	// for it on every call — or (b) the previous sweep was more
	// than window/4 ago. A linear sweep on every Seen() lets a
	// TSIG-flooder amplify CPU pressure rather than relieve it.
	if c.shouldSweepLocked(now) {
		c.evictExpiredLocked(now)
		c.lastSweep = now
	}

	if _, exists := c.seen[k]; exists {
		// Keep the original observation time. Refreshing on every
		// hit would let a persistent replayer pin its entry as
		// "fresh" forever while legitimate entries age out and get
		// preferentially evicted by evictOldestLocked. The entry
		// will age out on its own window — replays past that point
		// re-enter as fresh, which is the intended semantic since
		// the fudge window has already lapsed.
		return true
	}

	if c.size > 0 && len(c.seen) >= c.size {
		// Force a sweep at the cap before falling back to oldest-
		// eviction; a sweep often releases enough room without
		// touching live entries.
		c.evictExpiredLocked(now)
		c.lastSweep = now
		if len(c.seen) >= c.size {
			c.evictOldestLocked()
		}
	}
	c.seen[k] = now
	return false
}

// shouldSweepLocked decides whether the next Seen() call should run a
// linear expiration sweep.
func (c *MemoryReplayCache) shouldSweepLocked(now time.Time) bool {
	if c.size > 0 && len(c.seen) >= c.size/2 {
		return true
	}
	if c.window <= 0 {
		return false
	}
	if c.lastSweep.IsZero() {
		return true
	}
	return now.Sub(c.lastSweep) >= c.window/4
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
