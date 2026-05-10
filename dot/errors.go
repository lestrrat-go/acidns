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
