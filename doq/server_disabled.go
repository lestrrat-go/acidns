//go:build acidns_no_doq

package doq

import (
	"context"
	"crypto/tls"
	"net/netip"
	"time"

	"github.com/lestrrat-go/acidns"
)

// ServerOption is a no-op stub when the package is built with
// acidns_no_doq.
type ServerOption interface{ applyDoQServer() }

type stubServerOption struct{}

func (stubServerOption) applyDoQServer() {}

// WithServerTLSConfig is a no-op stub.
func WithServerTLSConfig(*tls.Config) ServerOption { return stubServerOption{} }

// WithServerIdleTimeout is a no-op stub.
func WithServerIdleTimeout(time.Duration) ServerOption { return stubServerOption{} }

// WithServerStreamReadTimeout is a no-op stub.
func WithServerStreamReadTimeout(time.Duration) ServerOption { return stubServerOption{} }

// WithServerWriteTimeout is a no-op stub.
func WithServerWriteTimeout(time.Duration) ServerOption { return stubServerOption{} }

// WithServerMaxMessageSize is a no-op stub.
func WithServerMaxMessageSize(int) ServerOption { return stubServerOption{} }

// WithServerMaxStreamsPerConn is a no-op stub.
func WithServerMaxStreamsPerConn(int) ServerOption { return stubServerOption{} }

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

func (*Controller) Addr() netip.AddrPort   { return netip.AddrPort{} }
func (*Controller) Done() <-chan struct{}  { ch := make(chan struct{}); close(ch); return ch }
func (*Controller) Err() error             { return ErrDoQDisabled }
func (*Controller) Wait() error            { return ErrDoQDisabled }
