package validator

import (
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/acidns/dnssec"
	"github.com/lestrrat-go/acidns/dnssec/validator/validatorbb"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/option/v3"
)

// ErrNoCoveringRRSIG is returned when a validation request supplies an
// RRset with no matching RRSIG.
var ErrNoCoveringRRSIG = errors.New("validator: no covering RRSIG")

// ErrBogus is the umbrella sentinel for any [Bogus] outcome — every
// concrete bogus-reason error wraps it so callers can do a single
// errors.Is check to branch on "the validator decided this was bogus."
var ErrBogus = errors.New("validator: bogus")

// ErrNTAOverride is returned when an NTA in the configured store
// short-circuited validation to [Indeterminate]. Callers that want to
// surface this via Extended DNS Errors (RFC 8914) can check for this
// sentinel via errors.Is.
var ErrNTAOverride = errors.New("validator: covered by negative trust anchor")

// ErrNSECDenialNXDOMAIN is returned by NSEC/NSEC3 denial-of-existence
// proof helpers when the chain proves the queried name does not
// exist (NXDOMAIN). The wrapped error supplies the concrete reason
// (closest-encloser found, NSEC record covering the gap, etc.).
var ErrNSECDenialNXDOMAIN = errors.New("validator: NSEC proves NXDOMAIN")

// ErrNSECDenialNoData is returned when the chain proves the queried
// name exists but has no records of the queried type (NoData).
var ErrNSECDenialNoData = errors.New("validator: NSEC proves NoData")

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

// Validator wraps the dnssec verification primitives with NTA support and
// a bogus-answer policy.
type Validator struct {
	cfg validatorConfig
}

// New returns a Validator. With no options the validator carries an
// empty NTA store, [BogusReturnSERVFAIL], and time.Now as its clock.
// The error return is currently always nil; it is part of the
// signature so future option-validation can be added without breaking
// callers.
func New(opts ...ValidatorOption) (*Validator, error) {
	c := validatorConfig{}
	for _, o := range opts {
		switch o.Ident() {
		case identValidatorNTAStore{}:
			c.ntas = option.MustGet[*NTAStore](o)
		case identValidatorBogusPolicy{}:
			c.bogusPolicy = option.MustGet[BogusPolicy](o)
		case identValidatorClock{}:
			c.now = option.MustGet[func() time.Time](o)
		case identValidatorClockSkew{}:
			if skew := option.MustGet[time.Duration](o); skew >= 0 {
				c.skew = skew
			}
		}
	}
	if c.ntas == nil {
		c.ntas = NewNTAStore()
	}
	if c.now == nil {
		c.now = time.Now
	}
	return &Validator{cfg: c}, nil
}

// NTAs exposes the validator's NTA store so callers can mutate it at
// runtime (e.g. add `.de` during an outage without restarting).
func (v *Validator) NTAs() *NTAStore { return v.cfg.ntas }

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
	if v.cfg.ntas.Covers(owner) {
		return Indeterminate, rdata.RRSIG{}, nil
	}
	if len(rrsigs) == 0 {
		return Bogus, rdata.RRSIG{}, ErrNoCoveringRRSIG
	}
	now := v.cfg.now()
	var lastErr error
	for _, sig := range rrsigs {
		if !validatorbb.RRSIGValidNowWithSkew(sig, now, v.cfg.skew) {
			lastErr = fmt.Errorf("validator: RRSIG inception/expiration outside now")
			continue
		}
		// RFC 4034 §5.4: keytag is non-unique. Try every DNSKEY whose
		// (alg, keytag) pair matches the signature; otherwise a hostile
		// signer can publish a same-keytag throwaway and DoS validation
		// against the legitimate key it sorts before.
		matched := 0
		var verifyErr error
		for _, key := range keys {
			if key.Algorithm() != sig.Algorithm() {
				continue
			}
			if dnssec.KeyTag(key) != sig.KeyTag() {
				continue
			}
			matched++
			err := dnssec.Verify(set, sig, key)
			if err == nil {
				return Secure, sig, nil
			}
			verifyErr = err
		}
		if matched == 0 {
			lastErr = fmt.Errorf("validator: no DNSKEY matches RRSIG %d/%d",
				sig.Algorithm(), sig.KeyTag())
			continue
		}
		lastErr = verifyErr
	}
	if v.cfg.bogusPolicy == BogusReturnAnswer {
		return Bogus, rdata.RRSIG{}, lastErr
	}
	return Bogus, rdata.RRSIG{}, fmt.Errorf("validator: %w", lastErr)
}

// VerifyDelegation checks that the supplied DNSKEY set chains to a parent
// zone via at least one of the parent's DS records. Use for stepping the
// chain-of-trust walk. The owner name is the DELEGATION POINT (i.e. the
// child zone's apex) — it is also what the NTA store is consulted with.
func (v *Validator) VerifyDelegation(owner wire.Name, dsRecords []rdata.DS, keys []rdata.DNSKEY) (Result, error) {
	if v.cfg.ntas.Covers(owner) {
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

// findMatchingKey returns the first DNSKEY whose (alg, keytag) matches
// sig. Retained for callers that want to peek at "any matching key";
// verification paths use the loop in ValidateRRset / verifyRRsetWithKeys
// directly so collisions are exhausted instead of breaking on first match.
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
