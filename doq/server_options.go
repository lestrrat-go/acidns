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
	tlsConfig         *tls.Config
	idleTimeout       time.Duration
	streamReadTimeout time.Duration
	writeTimeout      time.Duration
	maxMessageSize    int
	maxStreamsPer     int
	maxConnections    int
}

// WithServerTLSConfig installs the TLS configuration used during the
// QUIC handshake. Required: a DoQ server without TLS isn't DoQ.
// MinVersion is raised to TLS 1.3 if unset; "doq" is appended to
// NextProtos when missing.
func WithServerTLSConfig(tc *tls.Config) ServerOption {
	return serverOptionFunc(func(c *serverConfig) { c.tlsConfig = tc })
}

// WithServerIdleTimeout caps how long a QUIC connection can be idle
// before the underlying library closes it. Maps to quic-go's
// MaxIdleTimeout. Defaults to 30 seconds. A non-positive value
// falls back to quic-go's default. This is the connection-level
// knob — for the per-stream read deadline that bounds how long the
// server waits for a query body, see [WithServerStreamReadTimeout].
func WithServerIdleTimeout(d time.Duration) ServerOption {
	return serverOptionFunc(func(c *serverConfig) { c.idleTimeout = d })
}

// WithServerStreamReadTimeout caps how long the server waits for a
// query body to arrive on a freshly-accepted stream. Distinct from
// [WithServerIdleTimeout] (which is the QUIC connection-level idle
// limit). Defaults to 10 seconds; non-positive disables. A short
// value here protects against a slow-write peer pinning per-stream
// state without yet sending any wire data.
func WithServerStreamReadTimeout(d time.Duration) ServerOption {
	return serverOptionFunc(func(c *serverConfig) { c.streamReadTimeout = d })
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

// WithServerMaxConnections caps the number of concurrent QUIC
// connections the server accepts. Once the cap is reached additional
// peers are closed with the doq "excessive load" error code per
// RFC 9250 §4.3. Defaults to 256; non-positive disables.
func WithServerMaxConnections(n int) ServerOption {
	return serverOptionFunc(func(c *serverConfig) { c.maxConnections = n })
}
