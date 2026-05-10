//go:build !acidns_no_doq

package doq

import (
	"crypto/tls"
	"time"

	"github.com/lestrrat-go/option/v3"
)

// ServerOption configures a DoQ [Server].
type ServerOption interface {
	option.Interface
	doqServerOption()
}

type doqServerOption struct{ option.Interface }

func (doqServerOption) doqServerOption() {}

type serverConfig struct {
	tlsConfig         *tls.Config
	handshakeTimeout  time.Duration
	idleTimeout       time.Duration
	streamReadTimeout time.Duration
	writeTimeout      time.Duration
	maxMessageSize    int
	maxStreamsPer     int
	maxConnections    int
	maxConnLifetime   time.Duration
}

type identServerTLSConfig struct{}
type identServerHandshakeTimeout struct{}
type identServerIdleTimeout struct{}
type identServerStreamReadTimeout struct{}
type identServerWriteTimeout struct{}
type identServerMaxMessageSize struct{}
type identServerMaxStreamsPer struct{}
type identServerMaxConnections struct{}
type identServerMaxConnLifetime struct{}

// WithServerTLSConfig installs the TLS configuration used during the
// QUIC handshake. Required: a DoQ server without TLS isn't DoQ.
// MinVersion is raised to TLS 1.3 if unset; "doq" is appended to
// NextProtos when missing.
func WithServerTLSConfig(tc *tls.Config) ServerOption {
	return doqServerOption{option.New(identServerTLSConfig{}, tc)}
}

// WithServerHandshakeTimeout caps how long the QUIC handshake may
// take. A slow-handshake peer that opens a connection and never
// finishes ClientHello → 1-RTT can otherwise pin per-connection
// state on the server. Distinct from [WithServerIdleTimeout] (which
// applies to established connections). Defaults to 10s; non-positive
// disables.
func WithServerHandshakeTimeout(d time.Duration) ServerOption {
	return doqServerOption{option.New(identServerHandshakeTimeout{}, d)}
}

// WithServerIdleTimeout caps how long a QUIC connection can be idle
// before the underlying library closes it. Maps to quic-go's
// MaxIdleTimeout. Defaults to 30 seconds. A non-positive value
// falls back to quic-go's default. This is the connection-level
// knob — for the per-stream read deadline that bounds how long the
// server waits for a query body, see [WithServerStreamReadTimeout].
func WithServerIdleTimeout(d time.Duration) ServerOption {
	return doqServerOption{option.New(identServerIdleTimeout{}, d)}
}

// WithServerStreamReadTimeout caps how long the server waits for a
// query body to arrive on a freshly-accepted stream. Distinct from
// [WithServerIdleTimeout] (which is the QUIC connection-level idle
// limit). Defaults to 10 seconds; non-positive disables. A short
// value here protects against a slow-write peer pinning per-stream
// state without yet sending any wire data.
func WithServerStreamReadTimeout(d time.Duration) ServerOption {
	return doqServerOption{option.New(identServerStreamReadTimeout{}, d)}
}

// WithServerWriteTimeout caps how long a single response write may
// take on a stream. Defaults to 5 seconds; non-positive disables.
func WithServerWriteTimeout(d time.Duration) ServerOption {
	return doqServerOption{option.New(identServerWriteTimeout{}, d)}
}

// WithServerMaxMessageSize caps the length-prefixed body the server
// is willing to read from a single stream. Defaults to 16 KiB; the
// 16-bit length prefix permits up to 65535 bytes when uncapped.
// A non-positive value disables the cap.
func WithServerMaxMessageSize(n int) ServerOption {
	return doqServerOption{option.New(identServerMaxMessageSize{}, n)}
}

// WithServerMaxStreamsPerConn caps the number of concurrent
// bidirectional streams a single QUIC connection may open. Defaults
// to 256 — generous for any real client and tight enough that a
// hostile peer cannot exhaust per-connection state.
func WithServerMaxStreamsPerConn(n int) ServerOption {
	return doqServerOption{option.New(identServerMaxStreamsPer{}, n)}
}

// WithServerMaxConnections caps the number of concurrent QUIC
// connections the server accepts. Once the cap is reached additional
// peers are closed with the doq "excessive load" error code per
// RFC 9250 §4.3. Defaults to 256; non-positive disables.
func WithServerMaxConnections(n int) ServerOption {
	return doqServerOption{option.New(identServerMaxConnections{}, n)}
}

// WithServerMaxConnLifetime caps the wall-clock lifetime of a single
// QUIC connection. Without it a hostile peer can keep a connection
// alive indefinitely by re-opening streams just under the idle window
// — [WithServerMaxStreamsPerConn] caps simultaneous streams but not
// lifetime streams. Defaults to 1 hour, matching the TCP and DoT
// defaults. A non-positive value disables the cap.
func WithServerMaxConnLifetime(d time.Duration) ServerOption {
	return doqServerOption{option.New(identServerMaxConnLifetime{}, d)}
}
