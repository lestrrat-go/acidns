// Package validatorbb is the low-level DNSSEC-validator primitive layer
// ("building blocks") for [github.com/lestrrat-go/acidns/dnssec/validator].
// It exposes the pure helpers used by the chain Walker without depending on
// the validator's stateful types (Walker, Anchor, NTAStore, etc.).
//
// The functions here are deliberately small and side-effect-free so they
// can be unit-tested in isolation and reused by other DNSSEC tooling that
// needs the same canonical-form / NSEC / NSEC3 / RRSIG arithmetic.
//
// The parent [github.com/lestrrat-go/acidns/dnssec/validator] package wires
// these primitives into the chain-of-trust state machine.
package validatorbb
