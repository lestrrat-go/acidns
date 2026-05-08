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
)

// ErrDoQDisabled is returned by New when the package was built with the
// acidns_no_doq build tag.
var ErrDoQDisabled = errors.New("doq: disabled at build time (acidns_no_doq)")

// Option is a no-op stub; its methods are unreachable because New errors
// before they are applied.
type Option interface{ applyDoQ() }

// WithTimeout is a no-op stub.
func WithTimeout(time.Duration) Option { return stubOption{} }

// WithTLSConfig is a no-op stub.
func WithTLSConfig(*tls.Config) Option { return stubOption{} }

// WithServerName is a no-op stub.
func WithServerName(string) Option { return stubOption{} }

// WithPadding is a no-op stub.
func WithPadding(bool) Option { return stubOption{} }

type stubOption struct{}

func (stubOption) applyDoQ() {}

// New always returns ErrDoQDisabled in the stub build.
func New(_ netip.AddrPort, _ ...Option) (acidns.Exchanger, error) {
	return nil, ErrDoQDisabled
}
