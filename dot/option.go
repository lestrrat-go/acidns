package dot

import (
	"crypto/tls"
	"time"
)

// Option configures a DoT Exchanger.
type Option interface{ applyDoT(*config) }

type optionFunc func(*config)

func (f optionFunc) applyDoT(c *config) { f(c) }

type config struct {
	timeout    time.Duration
	tlsConfig  *tls.Config
	serverName string
	padding    bool
}

// WithTimeout sets a per-exchange timeout used when the caller's context
// has no deadline. Defaults to 10 seconds (TLS handshake adds overhead).
func WithTimeout(d time.Duration) Option {
	return optionFunc(func(c *config) { c.timeout = d })
}

// WithTLSConfig overrides the default TLS configuration. Use this to pin
// certificates, supply a custom RootCAs pool, or enable session resumption.
// The provided config is cloned; mutations after construction are ignored.
func WithTLSConfig(tc *tls.Config) Option {
	return optionFunc(func(c *config) { c.tlsConfig = tc.Clone() })
}

// WithServerName overrides the SNI / certificate verification name. By
// default the address's host part is used; pass this option for IP-only
// servers whose certificate is bound to a hostname.
func WithServerName(name string) Option {
	return optionFunc(func(c *config) { c.serverName = name })
}

// WithPadding toggles RFC 8467 §4.1 block-padding. Default is true:
// outgoing queries are padded to a 128-byte boundary so an on-path
// observer cannot infer the queried name from the encrypted record's
// length. Pass false to disable padding — useful for byte-exact test
// fixtures and for callers that pre-pad queries themselves.
func WithPadding(v bool) Option {
	return optionFunc(func(c *config) { c.padding = v })
}
