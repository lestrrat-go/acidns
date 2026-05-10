package tsig

import (
	"time"

	"github.com/lestrrat-go/option/v3"
)

// ReplayCacheOption configures a [MemoryReplayCache] at construction.
type ReplayCacheOption interface {
	option.Interface
	tsigReplayCacheOption()
}

type tsigReplayCacheOption struct{ option.Interface }

func (tsigReplayCacheOption) tsigReplayCacheOption() {}

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
// after that interval. Set this to match the fudge passed to
// [Verify]; the receiver only accepts signatures whose timestamp is
// within fudge of "now," so an entry older than fudge cannot be a
// live replay anyway.
func WithReplayWindow(d time.Duration) ReplayCacheOption {
	return tsigReplayCacheOption{option.New(identReplayWindow{}, d)}
}

// WithReplayCacheSize sets the maximum number of distinct verified
// signatures retained simultaneously. A non-positive value disables
// the size cap (eviction then runs purely on age).
func WithReplayCacheSize(n int) ReplayCacheOption {
	return tsigReplayCacheOption{option.New(identReplayCacheSize{}, n)}
}

// WithReplayClock injects a clock for tests. Defaults to time.Now.
func WithReplayClock(now func() time.Time) ReplayCacheOption {
	return tsigReplayCacheOption{option.New(identReplayClock{}, now)}
}

// KeyOption configures a [Key] at construction.
type KeyOption interface {
	option.Interface
	tsigKeyOption()
}

type tsigKeyOption struct{ option.Interface }

func (tsigKeyOption) tsigKeyOption() {}

type identKeyAllowSHA1 struct{}

// WithAllowSHA1 marks a Key as permitted to operate under
// [HMACSHA1]. RFC 8945 §6 still lists HMAC-SHA1 as
// MUST-implement, but it is operationally deprecated and
// discouraged for new deployments. By default a Key constructed
// with HMACSHA1 fails Sign and Verify with [ErrSHA1Disabled];
// passing this option (with true) re-enables SHA-1 for
// interoperability with legacy peers. Has no effect on keys
// using stronger algorithms.
func WithAllowSHA1(allow bool) KeyOption {
	return tsigKeyOption{option.New(identKeyAllowSHA1{}, allow)}
}
