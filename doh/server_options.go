package doh

import (
	"crypto/tls"
	"time"

	"github.com/lestrrat-go/option/v3"
)

// HandlerOption configures the http.Handler returned by [NewHandler].
type HandlerOption interface {
	option.Interface
	dohHandlerOption()
}

type dohHandlerOption struct{ option.Interface }

func (dohHandlerOption) dohHandlerOption() {}

type handlerConfig struct {
	maxRequestBytes int
}

type identHandlerMaxRequestBytes struct{}

// WithHandlerMaxRequestBytes caps the size of the wire-format DNS
// request the handler will accept. Defaults to [MaxRequestBytes];
// useful in deployments where a tighter cap is desired.
func WithHandlerMaxRequestBytes(n int) HandlerOption {
	return dohHandlerOption{option.New(identHandlerMaxRequestBytes{}, n)}
}

// ServerOption configures the convenience [Server] returned by
// [NewServer]. These knobs map onto the underlying http.Server's
// timeouts and TLS configuration plus a small DoH-specific layer.
type ServerOption interface {
	option.Interface
	dohServerOption()
}

type dohServerOption struct{ option.Interface }

func (dohServerOption) dohServerOption() {}

type serverConfig struct {
	tlsConfig            *tls.Config
	path                 string
	maxRequestBytes      int
	readHeaderTimeout    time.Duration
	readTimeout          time.Duration
	writeTimeout         time.Duration
	idleTimeout          time.Duration
	maxConnections       int
	maxConcurrentStreams uint32
}

type identServerTLSConfig struct{}
type identServerPath struct{}
type identServerMaxRequestBytes struct{}
type identServerReadHeaderTimeout struct{}
type identServerReadTimeout struct{}
type identServerWriteTimeout struct{}
type identServerIdleTimeout struct{}
type identServerMaxConnections struct{}
type identServerMaxConcurrentStreams struct{}

// WithServerTLSConfig installs the TLS configuration. The supplied
// config MUST carry at least one Certificate (or a GetCertificate
// callback). The config is cloned; mutations after construction are
// ignored. If MinVersion is 0 the server raises it to TLS 1.3.
// "h2" and "http/1.1" are appended to NextProtos when missing.
//
// Required — [NewServer] returns an error otherwise.
func WithServerTLSConfig(tc *tls.Config) ServerOption {
	return dohServerOption{option.New(identServerTLSConfig{}, tc)}
}

// WithServerPath sets the URL path on which the handler responds.
// Defaults to "/dns-query" per RFC 8484 §3. Operators with extant
// HTTP routing should plug [NewHandler] into their existing mux
// instead.
func WithServerPath(p string) ServerOption {
	return dohServerOption{option.New(identServerPath{}, p)}
}

// WithServerMaxRequestBytes caps the wire-format DNS request body.
// Defaults to [MaxRequestBytes].
func WithServerMaxRequestBytes(n int) ServerOption {
	return dohServerOption{option.New(identServerMaxRequestBytes{}, n)}
}

// WithServerReadHeaderTimeout caps how long the server waits for
// HTTP request headers. Maps to http.Server.ReadHeaderTimeout.
// Defaults to 10s.
func WithServerReadHeaderTimeout(d time.Duration) ServerOption {
	return dohServerOption{option.New(identServerReadHeaderTimeout{}, d)}
}

// WithServerReadTimeout caps how long the server waits for the full
// HTTP request (headers + body). Defaults to 30s.
func WithServerReadTimeout(d time.Duration) ServerOption {
	return dohServerOption{option.New(identServerReadTimeout{}, d)}
}

// WithServerWriteTimeout caps how long the server has to write the
// full response. Defaults to 30s.
func WithServerWriteTimeout(d time.Duration) ServerOption {
	return dohServerOption{option.New(identServerWriteTimeout{}, d)}
}

// WithServerIdleTimeout caps how long an HTTP keep-alive connection
// can remain idle between requests. Defaults to 60s.
func WithServerIdleTimeout(d time.Duration) ServerOption {
	return dohServerOption{option.New(identServerIdleTimeout{}, d)}
}

// WithServerMaxConnections caps the number of concurrently-accepted
// TCP connections. Excess connections block in the kernel listen
// backlog and are accepted as slots free up. Mirrors the dot.Server
// default of 1024. A non-positive value disables the cap.
func WithServerMaxConnections(n int) ServerOption {
	return dohServerOption{option.New(identServerMaxConnections{}, n)}
}

// WithServerMaxConcurrentStreams caps HTTP/2's per-connection
// concurrent stream count. Without this, a single TLS session can
// open ~100 streams (Go's http2 default) and pin that many
// concurrent ServeDNS goroutines per peer. A non-positive value
// disables the cap (http2 default applies).
func WithServerMaxConcurrentStreams(n uint32) ServerOption {
	return dohServerOption{option.New(identServerMaxConcurrentStreams{}, n)}
}
