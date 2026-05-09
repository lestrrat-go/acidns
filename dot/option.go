package dot

import (
	"crypto/tls"
	"time"

	"github.com/lestrrat-go/option/v3"
)

// Option configures the basic single-shot DoT Exchanger ([New]).
// Distinct from [KeepAliveOption] (the persistent-connection
// variant, [NewKeepAliveExchanger]) and [ServerOption] (the listen
// side, [NewServer]); the three option-sets share concept names
// (timeout, TLS config) but the Go type system enforces which
// constructor accepts which option, so the unprefixed names here
// match the unprefixed constructor.
type Option interface {
	option.Interface
	dotOption()
}

type dotOption struct{ option.Interface }

func (dotOption) dotOption() {}

type config struct {
	timeout    time.Duration
	tlsConfig  *tls.Config
	serverName string
	padding    bool
}

type identTimeout struct{}
type identTLSConfig struct{}
type identServerName struct{}
type identPadding struct{}

// WithTimeout sets a per-exchange timeout used when the caller's
// context has no deadline. Defaults to 10 seconds (TLS handshake
// adds overhead). Pass 0 to disable the fallback — the caller's
// context deadline or the kernel socket timeout becomes the only
// bound.
func WithTimeout(d time.Duration) Option {
	return dotOption{option.New(identTimeout{}, d)}
}

// WithTLSConfig overrides the default TLS configuration. Use this to pin
// certificates, supply a custom RootCAs pool, or enable session resumption.
// The provided config is cloned; mutations after construction are ignored.
func WithTLSConfig(tc *tls.Config) Option {
	return dotOption{option.New(identTLSConfig{}, tc.Clone())}
}

// WithServerName overrides the SNI / certificate verification name. By
// default the address's host part is used; pass this option for IP-only
// servers whose certificate is bound to a hostname.
func WithServerName(name string) Option {
	return dotOption{option.New(identServerName{}, name)}
}

// WithPadding toggles RFC 8467 §4.1 block-padding. Default is true:
// outgoing queries are padded to a 128-byte boundary so an on-path
// observer cannot infer the queried name from the encrypted record's
// length. Pass false to disable padding — useful for byte-exact test
// fixtures and for callers that pre-pad queries themselves.
func WithPadding(v bool) Option {
	return dotOption{option.New(identPadding{}, v)}
}
