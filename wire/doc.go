// Package wire is the DNS wire-format codec — the central package of
// acidns. Every other transport, server, validator, and tooling layer
// composes on top of these primitives.
//
// # Messages
//
// The Message interface represents a parsed DNS protocol message. It is
// constructed by NewBuilder().…Build() (immutable thereafter) or by
// Unmarshal of a byte slice. Marshal serialises a Message back to wire
// bytes; Unmarshal parses wire bytes into a Message.
//
// # Records
//
// Each Record carries an owner Name, a class (rrtype.Class), a type
// (rrtype.Type), a TTL, and a typed RData payload. Construct records
// with NewRecord; extract typed payloads with [RDataAs] (preferred over
// naked type assertions, since it is checked by the rrtype constant).
//
// # EDNS
//
// EDNS(0) is exposed as a separate first-class object on Message —
// EDNS()/EDNSBuilder — so callers do not have to reach into the
// additional section to find the OPT pseudo-RR. Padding (RFC 7830) is
// available via PadEncrypted; the dot, doh, and doq transports invoke
// it automatically per RFC 8467 §4.1.
//
// # Names
//
// Domain names are wirebb.Name values, available in this package as the
// type alias Name. ParseName converts a textual name to a Name;
// MustParseName panics on invalid input and is intended for tests and
// constants.
//
// # Errors
//
// Parse failures from Unmarshal are returned as *MessageParseError,
// which carries the section, RR index, and byte offset where the
// failure occurred. errors.Is(err, ErrInvalidMessage) continues to work
// for callers that want sentinel matching.
//
// # Sub-packages
//
//   - rrtype: type and class constants (A, AAAA, MX, IN, CH, …).
//   - rdata:  per-RR typed payloads (rdata.A, rdata.MX, rdata.SVCB, …).
//   - wirebb: pure-function packer/unpacker primitives — the byte-level
//     codec layer below this package.
//   - wiretest: fixture builders for tests (Query, Response, NXDOMAIN, …).
package wire
