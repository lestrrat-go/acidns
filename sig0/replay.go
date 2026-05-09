package sig0

import (
	"encoding/hex"
	"sync"
	"time"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/option/v3"
)

// ReplayCache deduplicates verified SIG(0)-signed messages so a
// captured envelope cannot be re-played within the validity window.
// RFC 2931 leaves replay defence to the application; callers handling
// UPDATE, NOTIFY, or any other side-effecting opcode that arrives over
// a SIG(0)-protected channel are expected to consult one before
// treating a verified message as fresh.
//
// The recommended usage is to plug a cache into [VerifyWithReplay]:
//
//	cache := sig0.NewMemoryReplayCache()
//	body, err := sig0.VerifyWithReplay(msg, key, signer, time.Now(), cache)
//	if errors.Is(err, sig0.ErrReplay) { ... }
//
// Implementations MUST be safe for concurrent use.
type ReplayCache interface {
	// Seen records the (signer, inception, signature) tuple and
	// reports whether the tuple was already present. A true return
	// means the message is a replay of one already verified within
	// the cache's retention window and SHOULD be rejected.
	Seen(signer wire.Name, inception time.Time, signature []byte) bool
}

// DefaultReplayWindow defaults to 5 minutes — matches tsig and the
// typical SIG(0) validity windows operators configure.
const DefaultReplayWindow = 5 * time.Minute

// DefaultReplayCacheSize bounds the in-memory cache so a flood of
// distinct signatures cannot exhaust memory. Sized to match tsig.
const DefaultReplayCacheSize = 16384

// NewMemoryReplayCache returns an in-memory [ReplayCache] suitable
// for typical authoritative-server deployments accepting SIG(0)-signed
// updates.
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

	mu   sync.Mutex
	seen map[string]time.Time
}

// Seen reports whether (signer, inception, signature) was already
// present inside the retention window; if not, records it.
func (c *MemoryReplayCache) Seen(signer wire.Name, inception time.Time, signature []byte) bool {
	key := replayKey(signer, inception, signature)
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evictExpiredLocked(now)
	if _, ok := c.seen[key]; ok {
		return true
	}
	if c.size > 0 && len(c.seen) >= c.size {
		c.evictOldestLocked()
	}
	c.seen[key] = now
	return false
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
	var oldest time.Time
	first := true
	for k, t := range c.seen {
		if first || t.Before(oldest) {
			oldest = t
			oldestKey = k
			first = false
		}
	}
	if !first {
		delete(c.seen, oldestKey)
	}
}

func replayKey(signer wire.Name, inception time.Time, signature []byte) string {
	wn := signer.AppendWire(nil)
	// Inception is uint32 seconds on the wire. Hex-encoding the full
	// signature disambiguates two messages that happen to share
	// (signer, inception) when the signing key is rotated mid-second.
	return string(wn) + "\x00" + hexInt64(inception.Unix()) + "\x00" + hex.EncodeToString(signature)
}

func hexInt64(v int64) string {
	const hexDigits = "0123456789abcdef"
	var buf [16]byte
	for i := 0; i < 16; i++ {
		buf[15-i] = hexDigits[v&0xf]
		v >>= 4
	}
	return string(buf[:])
}
