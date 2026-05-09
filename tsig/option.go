package tsig

import "time"

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
