//go:build !acidns_no_doq

package doq

import (
	"crypto/tls"
	"time"
)

// Option configures a DoQ Exchanger.
type Option interface{ applyDoQ(*config) }

type optionFunc func(*config)

func (f optionFunc) applyDoQ(c *config) { f(c) }

type config struct {
	timeout    time.Duration
	tlsConfig  *tls.Config
	serverName string
	padding    bool
}

// WithTimeout sets a per-exchange timeout used when ctx has no deadline.
func WithTimeout(d time.Duration) Option {
	return optionFunc(func(c *config) { c.timeout = d })
}

// WithTLSConfig overrides the default TLS configuration. The "doq" ALPN
// is added automatically if absent.
func WithTLSConfig(tc *tls.Config) Option {
	return optionFunc(func(c *config) { c.tlsConfig = tc.Clone() })
}

// WithServerName overrides SNI / certificate verification name.
func WithServerName(name string) Option {
	return optionFunc(func(c *config) { c.serverName = name })
}

// WithPadding toggles RFC 8467 §4.1 block-padding. Default is true.
func WithPadding(v bool) Option {
	return optionFunc(func(c *config) { c.padding = v })
}
