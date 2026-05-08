// Package validator implements an RFC 4035 / 5155 chain-of-trust DNSSEC
// validator. It is structured as a chain Walker that issues iterative DS
// and DNSKEY queries against a delegation source and returns a typed
// Result (Secure, Insecure, Bogus, Indeterminate).
//
// # Negative trust anchors
//
// NTAs are first-class. NTAStore is a concurrency-safe in-memory store
// of names that the operator has explicitly opted out of validation
// for; the chain Walker consults it on every name and short-circuits to
// Insecure for names beneath an active NTA. The .de incident of 2025
// motivates this — a misconfigured TLD must be downgradeable in
// minutes, not after a release cycle.
//
// # BogusPolicy
//
// BogusPolicy chooses what the recursive resolver does with a Bogus
// answer: serve SERVFAIL with EDE 6 (RFC 8914), serve unchanged with
// AD=0, or fail closed. WithBogusPolicy on the recursive resolver wires
// this in.
//
// # Algorithm rollover
//
// The Walker enforces RFC 6840 §5.11: a zone advertising a DNSKEY
// algorithm in its DS set must produce an RRSIG with that algorithm
// over every signed RRset, otherwise validation fails closed.
//
// # Compact denial
//
// NSEC and NSEC3 denial-of-existence (RFC 4034 §5, RFC 5155) is
// recognised; closest-encloser proof, NXDOMAIN, NoData, and opt-out
// delegations are all consumed. RFC compact-denial draft processing is
// partial — IsCompactNXDOMAIN classifies but the bitmap walk is
// pending.
package validator
