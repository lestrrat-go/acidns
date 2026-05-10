//go:build !acidns_no_doq

package doq

import (
	"crypto/tls"
	"time"

	"github.com/lestrrat-go/option/v3"
)

// Option configures a DoQ Exchanger.
type Option interface {
	option.Interface
	doqOption()
}

type doqOption struct{ option.Interface }

func (doqOption) doqOption() {}

// DefaultMaxResponseBytes caps the body of a DoQ response a client
// will allocate per stream. The wire prefix is uint16 so the absolute
// ceiling is 65535; 16 KiB suffices for ordinary lookups while
// rejecting attacker-induced inflation. Callers that need larger
// bodies (XFR over DoQ) can raise via [WithMaxResponseBytes].
const DefaultMaxResponseBytes = 16 * 1024

type config struct {
	timeout          time.Duration
	tlsConfig        *tls.Config
	serverName       string
	padding          bool
	insecure         bool
	maxResponseBytes int
}

type identTimeout struct{}
type identTLSConfig struct{}
type identServerName struct{}
type identPadding struct{}
type identInsecure struct{}
type identMaxResponseBytes struct{}

// WithTimeout sets a per-exchange timeout used when ctx has no deadline.
func WithTimeout(d time.Duration) Option {
	return doqOption{option.New(identTimeout{}, d)}
}

// WithTLSConfig overrides the default TLS configuration. The "doq" ALPN
// is added automatically if absent.
func WithTLSConfig(tc *tls.Config) Option {
	return doqOption{option.New(identTLSConfig{}, tc.Clone())}
}

// WithServerName overrides SNI / certificate verification name.
func WithServerName(name string) Option {
	return doqOption{option.New(identServerName{}, name)}
}

// WithPadding toggles RFC 8467 §4.1 block-padding. Default is true.
func WithPadding(v bool) Option {
	return doqOption{option.New(identPadding{}, v)}
}

// WithInsecure disables TLS certificate verification on the QUIC
// handshake. Use only against a known loopback / test endpoint —
// disabling verification on a public network strips DoQ of every
// authentication property the transport is meant to provide. The TLS
// 1.3 floor (RFC 9250 §4.1) is preserved.
func WithInsecure(v bool) Option {
	return doqOption{option.New(identInsecure{}, v)}
}

// WithMaxResponseBytes caps how many response bytes the client will
// allocate per stream. A non-positive value falls back to
// [DefaultMaxResponseBytes].
func WithMaxResponseBytes(n int) Option {
	return doqOption{option.New(identMaxResponseBytes{}, n)}
}
