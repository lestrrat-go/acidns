package sig0

import (
	"time"

	"github.com/lestrrat-go/option/v3"
)

// ReplayCacheOption configures a [MemoryReplayCache] at construction.
type ReplayCacheOption interface {
	option.Interface
	sig0ReplayCacheOption()
}

type sig0ReplayCacheOption struct{ option.Interface }

func (sig0ReplayCacheOption) sig0ReplayCacheOption() {}

type replayCacheConfig struct {
	size   int
	window time.Duration
	now    func() time.Time
}

type identReplayWindow struct{}
type identReplayCacheSize struct{}
type identReplayClock struct{}

// WithReplayWindow sets the retention window. Entries older than the
// window are evicted and the same signature can re-enter the cache
// after that interval. Set this to match the SIG(0) validity window
// passed to [Sign]; the receiver only accepts signatures whose
// inception is within the window of "now," so an entry older than
// the window cannot be a live replay anyway.
func WithReplayWindow(d time.Duration) ReplayCacheOption {
	return sig0ReplayCacheOption{option.New(identReplayWindow{}, d)}
}

// WithReplayCacheSize sets the maximum number of distinct verified
// signatures retained simultaneously. A non-positive value disables
// the size cap (eviction then runs purely on age).
func WithReplayCacheSize(n int) ReplayCacheOption {
	return sig0ReplayCacheOption{option.New(identReplayCacheSize{}, n)}
}

// WithReplayClock injects a clock for tests. Defaults to time.Now.
func WithReplayClock(now func() time.Time) ReplayCacheOption {
	return sig0ReplayCacheOption{option.New(identReplayClock{}, now)}
}
