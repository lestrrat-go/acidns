package cookies

import (
	"context"
	"log/slog"
	"time"

	"github.com/lestrrat-go/option/v3"
)

// ClientOption configures a [Client] returned by [NewClient].
type ClientOption interface {
	option.Interface
	clientOption()
}

type clientOption struct{ option.Interface }

func (clientOption) clientOption() {}

// PoolOption configures a [SecretPool] returned by [NewSecretPool].
type PoolOption interface {
	option.Interface
	poolOption()
}

type poolOption struct{ option.Interface }

func (poolOption) poolOption() {}

// ServerOption configures the [Server] returned by [NewServer].
type ServerOption interface {
	option.Interface
	serverOption()
}

type serverOption struct{ option.Interface }

func (serverOption) serverOption() {}

type identClientMaxEntries struct{}
type identClientClock struct{}
type identClientLogger struct{}
type identPoolRotateEvery struct{}
type identPoolContext struct{}
type identPoolLogger struct{}
type identServerMaxAge struct{}
type identServerClockSkew struct{}

// WithClientMaxEntries caps the number of (server, cookie) tuples
// kept in memory. When the cap is reached the oldest-touched entry
// is evicted before a new one is inserted. A non-positive value
// disables the cap. Defaults to [DefaultClientMaxEntries].
func WithClientMaxEntries(n int) ClientOption {
	return clientOption{option.New(identClientMaxEntries{}, n)}
}

// WithClientClock injects a custom clock for the LRU eviction
// timestamps. Intended for tests; production callers should leave
// the default.
func WithClientClock(now func() time.Time) ClientOption {
	return clientOption{option.New(identClientClock{}, now)}
}

// WithPoolRotateEvery enables automatic rotation of the pool's
// HMAC secret on the supplied interval. A positive value MUST be
// paired with [WithPoolContext]; otherwise [NewSecretPool] returns
// [ErrPoolRotationNeedsContext]. The rotation goroutine exits when
// the supplied ctx is cancelled (or [SecretPool.Close] is called,
// which remains available for early shutdown). A non-positive value
// disables automatic rotation.
func WithPoolRotateEvery(d time.Duration) PoolOption {
	return poolOption{option.New(identPoolRotateEvery{}, d)}
}

// WithPoolContext binds the rotation goroutine started by
// [WithPoolRotateEvery] to ctx. When ctx is cancelled the
// goroutine exits. Required whenever [WithPoolRotateEvery] is set
// to a positive duration.
func WithPoolContext(ctx context.Context) PoolOption {
	return poolOption{option.New(identPoolContext{}, ctx)}
}

// WithClientLogger routes [Client] diagnostics (currently the
// one-shot RNG-failure warning emitted by [Client.Apply] when
// crypto/rand.Read returns an error) through the supplied
// logger. The default logger discards all output so importing
// this package does not pollute the host's stderr.
func WithClientLogger(l *slog.Logger) ClientOption {
	return clientOption{option.New(identClientLogger{}, l)}
}

// WithPoolLogger routes [SecretPool] diagnostics (currently the
// rotation-goroutine panic recovery message) through the supplied
// logger. The default logger discards all output.
func WithPoolLogger(l *slog.Logger) PoolOption {
	return poolOption{option.New(identPoolLogger{}, l)}
}

// WithMaxAge sets the cookie acceptance window. RFC 7873 §5.2.5
// recommends ~1 hour; that is the default if this option is not set.
func WithMaxAge(d time.Duration) ServerOption {
	return serverOption{option.New(identServerMaxAge{}, d)}
}

// WithClockSkew sets how far in the future a cookie's embedded
// timestamp may be before Validate returns ErrCookieExpired. Operators
// who want stricter clock alignment can pass a smaller value (e.g.
// 30 s); pass 0 to keep the default of [DefaultMaxFutureSkew].
func WithClockSkew(d time.Duration) ServerOption {
	return serverOption{option.New(identServerClockSkew{}, d)}
}
