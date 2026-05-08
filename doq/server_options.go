//go:build !acidns_no_doq

package doq

import (
	"crypto/tls"
	"time"
)

// ServerOption configures a DoQ [Server].
type ServerOption interface {
	applyDoQServer(*serverConfig)
}

type serverOptionFunc func(*serverConfig)

func (f serverOptionFunc) applyDoQServer(c *serverConfig) { f(c) }

type serverConfig struct {
	tlsConfig      *tls.Config
	idleTimeout    time.Duration
	writeTimeout   time.Duration
	maxMessageSize int
	maxStreamsPer  int
}

// WithServerTLSConfig installs the TLS configuration used during the
// QUIC handshake. Required: a DoQ server without TLS isn't DoQ.
// MinVersion is raised to TLS 1.3 if unset; "doq" is appended to
// NextProtos when missing.
func WithServerTLSConfig(tc *tls.Config) ServerOption {
	return serverOptionFunc(func(c *serverConfig) { c.tlsConfig = tc })
}

// WithServerIdleTimeout caps how long a QUIC connection or stream
// can be idle before the underlying library closes it. Defaults to
// 30 seconds. A non-positive value falls back to quic-go's default.
func WithServerIdleTimeout(d time.Duration) ServerOption {
	return serverOptionFunc(func(c *serverConfig) { c.idleTimeout = d })
}

// WithServerWriteTimeout caps how long a single response write may
// take on a stream. Defaults to 5 seconds; non-positive disables.
func WithServerWriteTimeout(d time.Duration) ServerOption {
	return serverOptionFunc(func(c *serverConfig) { c.writeTimeout = d })
}

// WithServerMaxMessageSize caps the length-prefixed body the server
// is willing to read from a single stream. Defaults to 16 KiB; the
// 16-bit length prefix permits up to 65535 bytes when uncapped.
// A non-positive value disables the cap.
func WithServerMaxMessageSize(n int) ServerOption {
	return serverOptionFunc(func(c *serverConfig) { c.maxMessageSize = n })
}

// WithServerMaxStreamsPerConn caps the number of concurrent
// bidirectional streams a single QUIC connection may open. Defaults
// to 256 — generous for any real client and tight enough that a
// hostile peer cannot exhaust per-connection state.
func WithServerMaxStreamsPerConn(n int) ServerOption {
	return serverOptionFunc(func(c *serverConfig) { c.maxStreamsPer = n })
}
