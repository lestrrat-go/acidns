package validator

import (
	"time"

	"github.com/lestrrat-go/option/v3"
)

// ValidatorOption configures a [Validator] at construction. Distinct
// from [WalkerOption] because the same package hosts both types and
// the option-set names already collide on the walker side; a single
// shared interface would either require the walker options to
// implement an unused validator marker, or vice versa. The names
// below mirror the walker option-set with a Validator prefix.
type ValidatorOption interface { //nolint:revive // intentionally mirrors WalkerOption in this same package; see godoc above.
	option.Interface
	validatorOption()
}

type validatorOption struct{ option.Interface }

func (validatorOption) validatorOption() {}

type validatorConfig struct {
	ntas        *NTAStore
	bogusPolicy BogusPolicy
	now         func() time.Time
	skew        time.Duration
}

type identValidatorNTAStore struct{}
type identValidatorBogusPolicy struct{}
type identValidatorClock struct{}
type identValidatorClockSkew struct{}

// WithValidatorNTAStore installs a Negative Trust Anchor store on
// the validator. Names covered by the store short-circuit validation
// to Indeterminate per RFC 7646. A nil store is equivalent to
// passing no option — a fresh empty store is allocated by [New].
func WithValidatorNTAStore(s *NTAStore) ValidatorOption {
	return validatorOption{option.New(identValidatorNTAStore{}, s)}
}

// WithValidatorBogusPolicy controls how the validator handles
// signature failures. Defaults to [BogusReturnSERVFAIL].
func WithValidatorBogusPolicy(p BogusPolicy) ValidatorOption {
	return validatorOption{option.New(identValidatorBogusPolicy{}, p)}
}

// WithValidatorClock injects a clock used for RRSIG
// inception/expiration checks. Defaults to time.Now. Test-only —
// production code should leave this unset. The bare-name spelling
// matches the Walker's WithWalkerClock.
func WithValidatorClock(now func() time.Time) ValidatorOption {
	return validatorOption{option.New(identValidatorClock{}, now)}
}

// WithValidatorClockSkew widens the RRSIG inception/expiration window by
// skew on each side. Production deployments typically pick 5–15
// minutes; the default of 0 is the conservative reading of RFC 4035
// §5.3. Mirrors the walker's WithWalkerClockSkew.
func WithValidatorClockSkew(skew time.Duration) ValidatorOption {
	return validatorOption{option.New(identValidatorClockSkew{}, skew)}
}

// WalkerOption configures a Walker.
type WalkerOption interface {
	option.Interface
	walkerOption()
}

type walkerOptionImpl struct{ option.Interface }

func (walkerOptionImpl) walkerOption() {}

type identWalkerAnchors struct{}
type identWalkerIANARootAnchor struct{}
type identWalkerNTAStore struct{}
type identWalkerBogusPolicy struct{}
type identWalkerClock struct{}
type identWalkerClockSkew struct{}
type identWalkerMaxZoneCuts struct{}
type identWalkerMaxRRSIGsTry struct{}
type identWalkerMaxAlgorithms struct{}
type identWalkerMaxKeysPerZone struct{}

// WithWalkerAnchors configures one or more trust anchors. The walker
// selects the closest covering anchor for each query. An unconfigured
// walker returns [ErrNoTrustAnchor] — pass this option (or
// [WithWalkerIANARootAnchor]) explicitly.
func WithWalkerAnchors(anchors ...Anchor) WalkerOption {
	return walkerOptionImpl{option.New(identWalkerAnchors{}, anchors)}
}

// WithWalkerIANARootAnchor opts in to the embedded IANA root KSK trust
// anchor (see [IANARootAnchor]). The pinned KSK digests will need to
// be refreshed at each ICANN KSK rollover; production deployments
// SHOULD instead manage their own RFC 5011 trust-anchor file and pass
// it via [WithWalkerAnchors].
//
// BREAKING: prior versions auto-installed IANARootAnchor when no
// anchor was configured; that default was removed because "I forgot to
// configure" should not silently look like "I want IANA root with a
// frozen-in-binary digest."
func WithWalkerIANARootAnchor(v bool) WalkerOption {
	return walkerOptionImpl{option.New(identWalkerIANARootAnchor{}, v)}
}

// WithWalkerNTAStore plugs in an existing NTA store. If unset, an
// empty store is allocated. NTAs short-circuit validation for
// covered names; cf. the project's DNSSEC stance.
func WithWalkerNTAStore(s *NTAStore) WalkerOption {
	return walkerOptionImpl{option.New(identWalkerNTAStore{}, s)}
}

// WithWalkerBogusPolicy sets the policy applied when validation
// fails. Default is BogusReturnSERVFAIL (the strict reading of RFC
// 4035 §5.5).
func WithWalkerBogusPolicy(p BogusPolicy) WalkerOption {
	return walkerOptionImpl{option.New(identWalkerBogusPolicy{}, p)}
}

// WithWalkerClock injects a clock. Tests use this to simulate
// signature inception and expiration without sleeping. Default is
// time.Now.
func WithWalkerClock(now func() time.Time) WalkerOption {
	return walkerOptionImpl{option.New(identWalkerClock{}, now)}
}

// WithWalkerClockSkew widens the RRSIG inception/expiration window
// by skew on each side. Production deployments typically pick 5–15
// minutes; the default of 0 is the conservative reading of RFC 4035
// §5.3.
func WithWalkerClockSkew(skew time.Duration) WalkerOption {
	return walkerOptionImpl{option.New(identWalkerClockSkew{}, skew)}
}

// WithWalkerMaxZoneCuts caps the depth of the chain walk. Default 16
// is enough for any real qname and prevents zone-cut bombs.
func WithWalkerMaxZoneCuts(n int) WalkerOption {
	return walkerOptionImpl{option.New(identWalkerMaxZoneCuts{}, n)}
}

// WithWalkerMaxRRSIGsTry caps the number of RRSIGs verified per
// RRset. Default 8. Without this cap a hostile zone could ship many
// RRSIGs to amplify CPU cost on a verifier.
func WithWalkerMaxRRSIGsTry(n int) WalkerOption {
	return walkerOptionImpl{option.New(identWalkerMaxRRSIGsTry{}, n)}
}

// WithWalkerMaxAlgorithms caps the number of distinct DNSSEC
// algorithms a single zone may advertise (DAU bomb guard). Default
// 4.
func WithWalkerMaxAlgorithms(n int) WalkerOption {
	return walkerOptionImpl{option.New(identWalkerMaxAlgorithms{}, n)}
}

// WithWalkerMaxKeysPerZone caps the number of usable DNSKEYs
// (post-protocol / post-revoke filter) the walker will accept from
// any single zone. Default 16. The cap defends against KeyTrap-style
// amplification (CVE-2023-50387): a zone publishing many DNSKEYs
// that share a keytag would otherwise drive maxRRSIGsTry × N
// candidate Verify calls per signed RRset.
func WithWalkerMaxKeysPerZone(n int) WalkerOption {
	return walkerOptionImpl{option.New(identWalkerMaxKeysPerZone{}, n)}
}
