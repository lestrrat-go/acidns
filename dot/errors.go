package dot

import "errors"

// ErrNilHandler is returned by [NewServer] when no handler is supplied.
var ErrNilHandler = errors.New("dot: handler is nil")

// ErrTLSConfigRequired is returned by [NewServer] when no
// [WithServerTLSConfig] is supplied. A DoT server without TLS is no
// longer DoT.
var ErrTLSConfigRequired = errors.New("dot: WithServerTLSConfig is required")

// ErrInvalidAddress is returned by [New] when the supplied server
// address fails to parse.
var ErrInvalidAddress = errors.New("dot: invalid server address")

// ErrServerNameRequired is returned by [New] when the address is an
// IP literal and no [WithServerName] (or *tls.Config.ServerName) was
// supplied.
var ErrServerNameRequired = errors.New("dot: WithServerName required when addr is an IP literal")

// ErrResponseTooLarge is returned by the server when a response would
// not fit in the 16-bit length-prefixed framing.
var ErrResponseTooLarge = errors.New("dot: response exceeds 65535 bytes")

// ErrInsecureTLSConfig is returned by [New] when the caller-supplied
// [WithTLSConfig] has [crypto/tls.Config.InsecureSkipVerify] set and
// [WithInsecure] was not also passed. Refusing the inherited
// misconfiguration avoids silently disabling certificate verification.
var ErrInsecureTLSConfig = errors.New("dot: tls.Config has InsecureSkipVerify=true without explicit WithInsecure(true)")

// ErrInvalidSPKIPin is returned by [New] when a [WithSPKIPin] value is
// not exactly 32 bytes (SHA-256 output length).
var ErrInvalidSPKIPin = errors.New("dot: SPKI pin must be 32 bytes (SHA-256)")

// ErrSPKIPinMismatch is returned from the TLS handshake when none of
// the pins registered via [WithSPKIPin] match the SHA-256 hash of the
// resolver's leaf certificate SubjectPublicKeyInfo (RFC 7858 §4.2).
var ErrSPKIPinMismatch = errors.New("dot: SPKI pin mismatch")

// ErrNoPeerCertificate is returned from the TLS handshake when the
// server presents no certificate but a [WithSPKIPin] was configured.
// In practice this can only happen on a misconfigured server.
var ErrNoPeerCertificate = errors.New("dot: no peer certificate")
