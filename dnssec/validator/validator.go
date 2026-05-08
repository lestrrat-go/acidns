package validator

import (
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/acidns/dnssec"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
)

// ErrNoCoveringRRSIG is returned when a validation request supplies an
// RRset with no matching RRSIG.
var ErrNoCoveringRRSIG = errors.New("validator: no covering RRSIG")

// Result classifies a validation outcome (RFC 4035 §4.3).
type Result int

const (
	// Secure: an unbroken chain to a configured trust anchor verified
	// each link.
	Secure Result = iota
	// Insecure: a delegation has no DS, or the answer is in an
	// unsigned zone.
	Insecure
	// Bogus: signatures are present but verification failed
	// (mismatched algorithm, wrong key tag, expired RRSIG, etc.).
	Bogus
	// Indeterminate: validation was skipped (NTA covers the name, or
	// the validator was given insufficient material to decide).
	Indeterminate
)

func (r Result) String() string {
	switch r {
	case Secure:
		return "secure"
	case Insecure:
		return "insecure"
	case Bogus:
		return "bogus"
	default:
		return "indeterminate"
	}
}

// BogusPolicy controls the validator's behaviour when verification fails.
type BogusPolicy int

const (
	// BogusReturnSERVFAIL discards the answer; callers should map this
	// to a SERVFAIL response (RFC 4035 §5.5).
	BogusReturnSERVFAIL BogusPolicy = iota
	// BogusReturnAnswer returns the unvalidated answer with Result=Bogus
	// so the caller can decide whether to surface it. This is the
	// configurable lever the .de incident motivates: short of an NTA,
	// some operators prefer "broken DNSSEC, working DNS" to a hard
	// outage.
	BogusReturnAnswer
)

// Options configures a Validator.
type Options struct {
	NTAs        *NTAStore
	BogusPolicy BogusPolicy
	Now         func() time.Time
}

// Validator wraps the dnssec verification primitives with NTA support and
// a bogus-answer policy.
type Validator struct {
	opts Options
}

// New returns a Validator. A nil NTAStore is replaced with a fresh empty
// one; Now defaults to time.Now.
func New(opts Options) *Validator {
	if opts.NTAs == nil {
		opts.NTAs = NewNTAStore()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Validator{opts: opts}
}

// NTAs exposes the validator's NTA store so callers can mutate it at
// runtime (e.g. add `.de` during an outage without restarting).
func (v *Validator) NTAs() *NTAStore { return v.opts.NTAs }

// ValidateRRset verifies set against the supplied DNSKEYs using one of the
// supplied RRSIGs. The owner name of set is consulted against the NTA
// store; a covered name short-circuits to Indeterminate without calling
// the verification primitives.
//
// Returns: result, the RRSIG that satisfied verification (zero-valued for
// non-Secure results), and the underlying error (only for Bogus when the
// policy is BogusReturnSERVFAIL or for caller programming errors).
func (v *Validator) ValidateRRset(set []wire.Record, rrsigs []rdata.RRSIG, keys []rdata.DNSKEY) (Result, rdata.RRSIG, error) {
	if len(set) == 0 {
		return Indeterminate, rdata.RRSIG{}, fmt.Errorf("validator: empty RRset")
	}
	owner := set[0].Name()
	if v.opts.NTAs.Covers(owner) {
		return Indeterminate, rdata.RRSIG{}, nil
	}
	if len(rrsigs) == 0 {
		return Bogus, rdata.RRSIG{}, ErrNoCoveringRRSIG
	}
	now := v.opts.Now()
	var lastErr error
	for _, sig := range rrsigs {
		if !rrsigValidNow(sig, now) {
			lastErr = fmt.Errorf("validator: RRSIG inception/expiration outside now")
			continue
		}
		key, ok := findMatchingKey(keys, sig)
		if !ok {
			lastErr = fmt.Errorf("validator: no DNSKEY matches RRSIG %d/%d",
				sig.Algorithm(), sig.KeyTag())
			continue
		}
		err := dnssec.Verify(set, sig, key)
		if err == nil {
			return Secure, sig, nil
		}
		lastErr = err
	}
	if v.opts.BogusPolicy == BogusReturnAnswer {
		return Bogus, rdata.RRSIG{}, lastErr
	}
	return Bogus, rdata.RRSIG{}, fmt.Errorf("validator: %w", lastErr)
}

// VerifyDelegation checks that the supplied DNSKEY set chains to a parent
// zone via at least one of the parent's DS records. Use for stepping the
// chain-of-trust walk. The owner name is the DELEGATION POINT (i.e. the
// child zone's apex) — it is also what the NTA store is consulted with.
func (v *Validator) VerifyDelegation(owner wire.Name, dsRecords []rdata.DS, keys []rdata.DNSKEY) (Result, error) {
	if v.opts.NTAs.Covers(owner) {
		return Indeterminate, nil
	}
	if len(dsRecords) == 0 {
		return Insecure, nil
	}
	for _, ds := range dsRecords {
		for _, key := range keys {
			if err := dnssec.VerifyDS(owner, ds, key); err == nil {
				return Secure, nil
			}
		}
	}
	return Bogus, fmt.Errorf("validator: no DS matched any DNSKEY for %s", owner)
}

func rrsigValidNow(sig rdata.RRSIG, now time.Time) bool {
	// Permit small clock skew either side; in practice the right place
	// for skew tolerance is a per-deployment knob, not here.
	if now.Before(sig.SignatureInception()) {
		return false
	}
	if now.After(sig.SignatureExpiration()) {
		return false
	}
	return true
}

func findMatchingKey(keys []rdata.DNSKEY, sig rdata.RRSIG) (rdata.DNSKEY, bool) {
	for _, k := range keys {
		if k.Algorithm() != sig.Algorithm() {
			continue
		}
		if dnssec.KeyTag(k) != sig.KeyTag() {
			continue
		}
		return k, true
	}
	return rdata.DNSKEY{}, false
}
