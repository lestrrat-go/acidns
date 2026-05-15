package dot

import (
	"crypto/tls"
	"time"

	"github.com/lestrrat-go/option/v3"
)

// ServerOption configures a DoT [Server] at construction. The shape
// mirrors [acidns.TCPListenerOption] one-for-one so a caller already
// familiar with the TCP server can map across.
type ServerOption interface {
	option.Interface
	dotServerOption()
}

type dotServerOption struct{ option.Interface }

func (dotServerOption) dotServerOption() {}

type serverConfig struct {
	tlsConfig          *tls.Config
	handshakeTimeout   time.Duration
	idleTimeout        time.Duration
	messageReadTimeout time.Duration
	writeTimeout       time.Duration
	maxConnections     int
	maxConnsPerSource  int
	maxMessageSize     int
	maxQueriesPerConn  int
	maxConnLifetime    time.Duration
	maxInflightPerConn     int
}

type identServerTLSConfig struct{}
type identServerHandshakeTimeout struct{}
type identServerIdleTimeout struct{}
type identServerMessageReadTimeout struct{}
type identServerWriteTimeout struct{}
type identServerMaxConnections struct{}
type identServerMaxConnsPerSource struct{}
type identServerMaxMessageSize struct{}
type identServerMaxQueriesPerConn struct{}
type identServerMaxConnLifetime struct{}
type identServerMaxInflightPerConn struct{}

// WithServerTLSConfig installs the TLS configuration used to serve
// connections. The supplied config MUST carry at least one
// Certificate (typical) or a GetCertificate callback (for SNI-based
// dispatch). The config is cloned; mutations after construction are
// ignored.
//
// If the supplied config has MinVersion=0 the server raises it to
// TLS 1.3. The "dot" ALPN identifier (RFC 7858 §3.2) is appended to
// NextProtos when missing.
//
// This option is required — [NewServer] returns an error otherwise.
func WithServerTLSConfig(tc *tls.Config) ServerOption {
	return dotServerOption{option.New(identServerTLSConfig{}, tc)}
}

// WithServerHandshakeTimeout caps how long the TLS handshake may
// take. Distinct from [WithServerIdleTimeout] so an operator can
// favour long-lived idle connections (e.g. 60s) without
// simultaneously widening the peer-stalls-on-ClientHello window.
// Defaults to 10s; non-positive disables.
func WithServerHandshakeTimeout(d time.Duration) ServerOption {
	return dotServerOption{option.New(identServerHandshakeTimeout{}, d)}
}

// WithServerIdleTimeout sets how long an idle connection is kept
// open between queries (RFC 7766 §6.5 applies to DoT via §3.4 of
// RFC 7858). Defaults to 10s. A non-positive value disables the
// idle timeout.
func WithServerIdleTimeout(d time.Duration) ServerOption {
	return dotServerOption{option.New(identServerIdleTimeout{}, d)}
}

// WithServerMessageReadTimeout caps how long the server will wait for
// the body bytes of a single message after the 2-byte length prefix
// has arrived. The idle timeout ([WithServerIdleTimeout]) governs the
// wait between messages; once a length prefix is in hand the peer is
// committed to delivering the body promptly, so this deadline is
// tighter. Without this distinction a peer that sends the prefix and
// then drips body bytes just under the idle interval can pin a slot
// for hours (idle * maxQueriesPerConn). Default 5s; non-positive
// disables the per-message deadline (falls back to the idle timeout
// for the body read as well).
func WithServerMessageReadTimeout(d time.Duration) ServerOption {
	return dotServerOption{option.New(identServerMessageReadTimeout{}, d)}
}

// WithServerWriteTimeout caps how long a single response write may
// take. Without a write deadline a slow-read attacker can pin a
// server goroutine indefinitely. Default 5s; non-positive disables.
func WithServerWriteTimeout(d time.Duration) ServerOption {
	return dotServerOption{option.New(identServerWriteTimeout{}, d)}
}

// WithServerMaxConnections caps the number of concurrent TLS
// connections. Once the cap is reached the accept loop blocks until
// a slot frees, providing natural backpressure via the kernel listen
// backlog. A non-positive value disables the cap. Defaults to 1024.
func WithServerMaxConnections(n int) ServerOption {
	return dotServerOption{option.New(identServerMaxConnections{}, n)}
}

// WithServerMaxConnsPerSource caps the number of concurrent TLS
// connections accepted from a single client IP. A single misbehaving
// peer cannot drain the global [WithServerMaxConnections] budget when
// this is set. Defaults to 32; non-positive disables.
func WithServerMaxConnsPerSource(n int) ServerOption {
	return dotServerOption{option.New(identServerMaxConnsPerSource{}, n)}
}

// WithServerMaxMessageSize caps the length-prefixed body the server
// is willing to read from a single query. The 16-bit length prefix
// permits up to 65535 bytes; without a tighter ceiling, a hostile
// client can force the server to allocate a 64 KiB buffer per
// connection. Default 16 KiB. A non-positive value disables the cap.
func WithServerMaxMessageSize(n int) ServerOption {
	return dotServerOption{option.New(identServerMaxMessageSize{}, n)}
}

// WithServerMaxQueriesPerConn caps the total queries served on a
// single connection before it is closed. A non-positive value
// disables the cap. Defaults to 0 (no cap).
func WithServerMaxQueriesPerConn(n int) ServerOption {
	return dotServerOption{option.New(identServerMaxQueriesPerConn{}, n)}
}

// WithServerMaxConnLifetime caps wall-clock time a single connection
// may remain open. Backstop for misbehaving peers and a way to cycle
// TLS session state on a sane cadence. A non-positive value disables.
func WithServerMaxConnLifetime(d time.Duration) ServerOption {
	return dotServerOption{option.New(identServerMaxConnLifetime{}, d)}
}

// WithServerMaxInflightPerConn caps the number of concurrently-running
// handler goroutines per connection. Defaults to 32; a non-positive
// value disables pipelining (handlers run serially).
func WithServerMaxInflightPerConn(n int) ServerOption {
	return dotServerOption{option.New(identServerMaxInflightPerConn{}, n)}
}
