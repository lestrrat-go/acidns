//go:build acidns_no_doq

package doq

import (
	"context"
	"crypto/tls"
	"net/netip"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/option/v3"
)

// ServerOption is a no-op stub when the package is built with
// acidns_no_doq.
type ServerOption interface {
	option.Interface
	doqServerOption()
}

type doqServerOption struct{ option.Interface }

func (doqServerOption) doqServerOption() {}

type identServerTLSConfig struct{}
type identServerIdleTimeout struct{}
type identServerStreamReadTimeout struct{}
type identServerWriteTimeout struct{}
type identServerMaxMessageSize struct{}
type identServerMaxStreamsPer struct{}

// WithServerTLSConfig is a no-op stub.
func WithServerTLSConfig(tc *tls.Config) ServerOption {
	return doqServerOption{option.New(identServerTLSConfig{}, tc)}
}

// WithServerIdleTimeout is a no-op stub.
func WithServerIdleTimeout(d time.Duration) ServerOption {
	return doqServerOption{option.New(identServerIdleTimeout{}, d)}
}

// WithServerStreamReadTimeout is a no-op stub.
func WithServerStreamReadTimeout(d time.Duration) ServerOption {
	return doqServerOption{option.New(identServerStreamReadTimeout{}, d)}
}

// WithServerWriteTimeout is a no-op stub.
func WithServerWriteTimeout(d time.Duration) ServerOption {
	return doqServerOption{option.New(identServerWriteTimeout{}, d)}
}

// WithServerMaxMessageSize is a no-op stub.
func WithServerMaxMessageSize(n int) ServerOption {
	return doqServerOption{option.New(identServerMaxMessageSize{}, n)}
}

// WithServerMaxStreamsPerConn is a no-op stub.
func WithServerMaxStreamsPerConn(n int) ServerOption {
	return doqServerOption{option.New(identServerMaxStreamsPer{}, n)}
}

// Server is a stub when DoQ is disabled at build time.
type Server struct{}

// NewServer always returns ErrDoQDisabled in the stub build.
func NewServer(_ netip.AddrPort, _ acidns.Handler, _ ...ServerOption) (*Server, error) {
	return nil, ErrDoQDisabled
}

// Run is unreachable in the stub build but kept for API symmetry.
func (*Server) Run(context.Context) (*Controller, error) { return nil, ErrDoQDisabled }

// Controller is a stub when DoQ is disabled.
type Controller struct{}

func (*Controller) Addr() netip.AddrPort  { return netip.AddrPort{} }
func (*Controller) Done() <-chan struct{} { ch := make(chan struct{}); close(ch); return ch }
func (*Controller) Err() error            { return ErrDoQDisabled }
func (*Controller) Wait() error           { return ErrDoQDisabled }
