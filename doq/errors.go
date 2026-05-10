package doq

import "errors"

// ErrNilHandler is returned by [NewServer] when no handler is supplied.
var ErrNilHandler = errors.New("doq: handler is nil")

// ErrTLSConfigRequired is returned by [NewServer] when no
// [WithServerTLSConfig] is supplied. RFC 9250 mandates TLS over QUIC.
var ErrTLSConfigRequired = errors.New("doq: WithServerTLSConfig is required")

// ErrInvalidAddress is returned by [New] when the supplied server
// address fails to parse.
var ErrInvalidAddress = errors.New("doq: invalid server address")

// ErrServerNameRequired is returned by [New] when the address is an
// IP literal and no [WithServerName] (or *tls.Config.ServerName) was
// supplied.
var ErrServerNameRequired = errors.New("doq: WithServerName required when addr is an IP literal")

// ErrResponseTooLarge is returned when a response would not fit in
// the 16-bit length-prefixed framing of an RFC 9250 stream.
var ErrResponseTooLarge = errors.New("doq: response exceeds 65535 bytes")

// ErrDuplicateWrite is returned by the server's [acidns.ResponseWriter]
// when WriteMsg is called more than once on a single QUIC stream.
var ErrDuplicateWrite = errors.New("doq: WriteMsg called twice on a single stream")
