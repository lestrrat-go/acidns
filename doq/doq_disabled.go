//go:build acidns_no_doq

// Package doq is a stub built when the acidns_no_doq build tag is set.
// New always returns ErrDoQDisabled and the package does not import
// quic-go, so callers can drop quic-go from their dependency tree.
package doq

import (
	"crypto/tls"
	"errors"
	"net/netip"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/option/v3"
)

// ErrDoQDisabled is returned by New when the package was built with the
// acidns_no_doq build tag.
var ErrDoQDisabled = errors.New("doq: disabled at build time (acidns_no_doq)")

// Option is a no-op stub; its methods are unreachable because New errors
// before they are applied.
type Option interface {
	option.Interface
	doqOption()
}

type doqOption struct{ option.Interface }

func (doqOption) doqOption() {}

type identTimeout struct{}
type identTLSConfig struct{}
type identServerName struct{}
type identPadding struct{}

// WithTimeout is a no-op stub.
func WithTimeout(d time.Duration) Option {
	return doqOption{option.New(identTimeout{}, d)}
}

// WithTLSConfig is a no-op stub.
func WithTLSConfig(tc *tls.Config) Option {
	return doqOption{option.New(identTLSConfig{}, tc)}
}

// WithServerName is a no-op stub.
func WithServerName(s string) Option {
	return doqOption{option.New(identServerName{}, s)}
}

// WithPadding is a no-op stub.
func WithPadding(v bool) Option {
	return doqOption{option.New(identPadding{}, v)}
}

// New always returns ErrDoQDisabled in the stub build.
func New(_ netip.AddrPort, _ ...Option) (acidns.Exchanger, error) {
	return nil, ErrDoQDisabled
}
