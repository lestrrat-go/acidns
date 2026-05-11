package dot

import (
	"crypto/tls"
	"time"

	"github.com/lestrrat-go/option/v3"
)

// Option configures the basic single-shot DoT Exchanger ([NewClient]).
// Distinct from [KeepAliveOption] (the persistent-connection
// variant, [NewKeepAliveClient]) and [ServerOption] (the listen
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
	insecure   bool
	spkiPins   [][]byte
}

type identTimeout struct{}
type identTLSConfig struct{}
type identServerName struct{}
type identPadding struct{}
type identInsecure struct{}
type identSPKIPin struct{}

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

// WithInsecure disables TLS certificate verification on outbound
// connections. By default the Client requires a valid chain to a
// system root or to the RootCAs configured via [WithTLSConfig]; pass
// true here to skip that check entirely. Use only against a known
// loopback / test endpoint — disabling verification on a public
// network strips DoT of every privacy and authentication property the
// transport is meant to provide. The TLS minimum-version floor is
// preserved (the option toggles only the cert chain, not the
// ciphersuite policy).
func WithInsecure(v bool) Option {
	return dotOption{option.New(identInsecure{}, v)}
}

// WithSPKIPin appends a SHA-256 SubjectPublicKeyInfo fingerprint (32
// raw bytes) the resolver's leaf certificate MUST match. RFC 7858 §4.2
// describes SPKI pinning as the recommended deployment posture for
// public DoT resolvers; Cloudflare, Quad9, and Google publish pin sets
// in this format.
//
// Multiple WithSPKIPin calls accumulate: at least one of the
// registered pins must match. Operators are encouraged to publish at
// least one backup pin so a key rotation can land without an outage
// (RFC 7858 §4.2).
//
// Pinning runs IN ADDITION TO the usual PKIX chain validation: a
// successful handshake requires both a valid certificate chain (or
// [WithInsecure](true)) AND a matching pin. The [crypto/tls.Config]
// returned by [WithTLSConfig] may carry its own VerifyConnection — if
// so, ours runs after the caller's, so the caller's check is
// preserved.
//
// Pin length is validated at [New]; supplying a non-32-byte pin
// returns [ErrInvalidSPKIPin].
func WithSPKIPin(pin []byte) Option {
	cp := make([]byte, len(pin))
	copy(cp, pin)
	return dotOption{option.New(identSPKIPin{}, cp)}
}

// WithPadding toggles RFC 8467 §4.1 block-padding. Default is true:
// outgoing queries are padded to a 128-byte boundary so an on-path
// observer cannot infer the queried name from the encrypted record's
// length. Pass false to disable padding — useful for byte-exact test
// fixtures and for callers that pre-pad queries themselves.
func WithPadding(v bool) Option {
	return dotOption{option.New(identPadding{}, v)}
}
