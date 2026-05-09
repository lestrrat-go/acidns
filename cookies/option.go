package cookies

import "time"

// ClientOption configures a [Client] returned by [NewClient].
type ClientOption interface{ applyClient(*clientConfig) }

type clientOptionFunc func(*clientConfig)

func (f clientOptionFunc) applyClient(c *clientConfig) { f(c) }

type clientConfig struct {
	maxEntries int
	now        func() time.Time
}

// WithClientMaxEntries caps the number of (server, cookie) tuples
// kept in memory. When the cap is reached the oldest-touched entry
// is evicted before a new one is inserted. A non-positive value
// disables the cap. Defaults to [DefaultClientMaxEntries].
func WithClientMaxEntries(n int) ClientOption {
	return clientOptionFunc(func(c *clientConfig) { c.maxEntries = n })
}

// WithClientClock injects a custom clock for the LRU eviction
// timestamps. Intended for tests; production callers should leave
// the default.
func WithClientClock(now func() time.Time) ClientOption {
	return clientOptionFunc(func(c *clientConfig) { c.now = now })
}

// PoolOption configures a [SecretPool] returned by [NewSecretPool].
type PoolOption interface{ applyPool(*poolConfig) }

type poolOptionFunc func(*poolConfig)

func (f poolOptionFunc) applyPool(c *poolConfig) { f(c) }

type poolConfig struct {
	rotateEvery time.Duration
}

// WithPoolRotateEvery enables automatic rotation of the pool's
// HMAC secret on the supplied interval. With auto-rotation enabled
// the returned pool's [SecretPool.Close] must be called on shutdown
// to stop the rotation goroutine. A non-positive value disables
// automatic rotation.
func WithPoolRotateEvery(d time.Duration) PoolOption {
	return poolOptionFunc(func(c *poolConfig) { c.rotateEvery = d })
}

// ServerOption configures the [Server] returned by [NewServer].
type ServerOption interface{ applyCookieServer(*serverConfig) }

type serverOptionFunc func(*serverConfig)

func (f serverOptionFunc) applyCookieServer(c *serverConfig) { f(c) }

type serverConfig struct {
	maxAge        time.Duration
	maxFutureSkew time.Duration
}

// WithMaxAge sets the cookie acceptance window. RFC 7873 §5.2.5
// recommends ~1 hour; that is the default if this option is not set.
func WithMaxAge(d time.Duration) ServerOption {
	return serverOptionFunc(func(c *serverConfig) {
		if d > 0 {
			c.maxAge = d
		}
	})
}

// WithClockSkew sets how far in the future a cookie's embedded
// timestamp may be before Validate returns ErrCookieExpired. Operators
// who want stricter clock alignment can pass a smaller value (e.g.
// 30 s); pass 0 to keep the default of [DefaultMaxFutureSkew].
func WithClockSkew(d time.Duration) ServerOption {
	return serverOptionFunc(func(c *serverConfig) {
		if d > 0 {
			c.maxFutureSkew = d
		}
	})
}
