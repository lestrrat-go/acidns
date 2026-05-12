//go:build acidns_no_doq

package doq

import (
	"crypto/tls"
	"net/netip"
	"time"

	"github.com/lestrrat-go/option/v3"
)

// KeepAliveOption is a no-op stub built when acidns_no_doq is set.
type KeepAliveOption interface {
	option.Interface
	doqKeepAliveOption()
}

type doqKeepAliveOption struct{ option.Interface }

func (doqKeepAliveOption) doqKeepAliveOption() {}

type identKATimeout struct{}
type identKAIdle struct{}
type identKATLSConfig struct{}
type identKAServerName struct{}
type identKAPadding struct{}
type identKAInsecure struct{}
type identKAMaxResponseBytes struct{}
type identKASPKIPin struct{}

// WithKeepAliveTimeout is a no-op stub.
func WithKeepAliveTimeout(d time.Duration) KeepAliveOption {
	return doqKeepAliveOption{option.New(identKATimeout{}, d)}
}

// WithKeepAliveMaxIdleTimeout is a no-op stub.
func WithKeepAliveMaxIdleTimeout(d time.Duration) KeepAliveOption {
	return doqKeepAliveOption{option.New(identKAIdle{}, d)}
}

// WithKeepAliveTLSConfig is a no-op stub.
func WithKeepAliveTLSConfig(tc *tls.Config) KeepAliveOption {
	return doqKeepAliveOption{option.New(identKATLSConfig{}, tc)}
}

// WithKeepAliveServerName is a no-op stub.
func WithKeepAliveServerName(s string) KeepAliveOption {
	return doqKeepAliveOption{option.New(identKAServerName{}, s)}
}

// WithKeepAlivePadding is a no-op stub.
func WithKeepAlivePadding(v bool) KeepAliveOption {
	return doqKeepAliveOption{option.New(identKAPadding{}, v)}
}

// WithKeepAliveInsecure is a no-op stub.
func WithKeepAliveInsecure(v bool) KeepAliveOption {
	return doqKeepAliveOption{option.New(identKAInsecure{}, v)}
}

// WithKeepAliveMaxResponseBytes is a no-op stub.
func WithKeepAliveMaxResponseBytes(n int) KeepAliveOption {
	return doqKeepAliveOption{option.New(identKAMaxResponseBytes{}, n)}
}

// WithKeepAliveSPKIPin is a no-op stub.
func WithKeepAliveSPKIPin(pin []byte) KeepAliveOption {
	cp := make([]byte, len(pin))
	copy(cp, pin)
	return doqKeepAliveOption{option.New(identKASPKIPin{}, cp)}
}

// KeepAliveClient is a stub; the constructor errors before any method
// can be invoked.
type KeepAliveClient struct{}

// Close is a no-op stub.
func (*KeepAliveClient) Close() error { return nil }

// NewKeepAliveClient always returns ErrDoQDisabled in the stub build.
func NewKeepAliveClient(_ netip.AddrPort, _ ...KeepAliveOption) (*KeepAliveClient, error) {
	return nil, ErrDoQDisabled
}
