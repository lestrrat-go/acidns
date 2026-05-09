package validator

import "time"

type walkerOptionFunc func(*walker)

func (f walkerOptionFunc) applyWalker(w *walker) { f(w) }

// WithWalkerAnchors configures one or more trust anchors. The walker
// selects the closest covering anchor for each query. An unconfigured
// walker returns [ErrNoTrustAnchor] — pass this option (or
// [WithWalkerIANARootAnchor]) explicitly.
func WithWalkerAnchors(anchors ...Anchor) WalkerOption {
	return walkerOptionFunc(func(w *walker) {
		w.anchors = append(w.anchors[:0], anchors...)
	})
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
func WithWalkerIANARootAnchor() WalkerOption {
	return walkerOptionFunc(func(w *walker) {
		w.anchors = append(w.anchors, IANARootAnchor())
	})
}

// WithWalkerNTAStore plugs in an existing NTA store. If unset, an
// empty store is allocated. NTAs short-circuit validation for
// covered names; cf. the project's DNSSEC stance.
func WithWalkerNTAStore(s *NTAStore) WalkerOption {
	return walkerOptionFunc(func(w *walker) {
		if s != nil {
			w.ntas = s
		}
	})
}

// WithWalkerBogusPolicy sets the policy applied when validation
// fails. Default is BogusReturnSERVFAIL (the strict reading of RFC
// 4035 §5.5).
func WithWalkerBogusPolicy(p BogusPolicy) WalkerOption {
	return walkerOptionFunc(func(w *walker) { w.bogusPolicy = p })
}

// WithWalkerClock injects a clock. Tests use this to simulate
// signature inception and expiration without sleeping. Default is
// time.Now.
func WithWalkerClock(now func() time.Time) WalkerOption {
	return walkerOptionFunc(func(w *walker) {
		if now != nil {
			w.now = now
		}
	})
}

// WithWalkerClockSkew widens the RRSIG inception/expiration window
// by skew on each side. Production deployments typically pick 5–15
// minutes; the default of 0 is the conservative reading of RFC 4035
// §5.3.
func WithWalkerClockSkew(skew time.Duration) WalkerOption {
	return walkerOptionFunc(func(w *walker) {
		if skew >= 0 {
			w.skew = skew
		}
	})
}

// WithWalkerMaxZoneCuts caps the depth of the chain walk. Default 16
// is enough for any real qname and prevents zone-cut bombs.
func WithWalkerMaxZoneCuts(n int) WalkerOption {
	return walkerOptionFunc(func(w *walker) {
		if n > 0 {
			w.maxZoneCuts = n
		}
	})
}

// WithWalkerMaxRRSIGsTry caps the number of RRSIGs verified per
// RRset. Default 8. Without this cap a hostile zone could ship many
// RRSIGs to amplify CPU cost on a verifier.
func WithWalkerMaxRRSIGsTry(n int) WalkerOption {
	return walkerOptionFunc(func(w *walker) {
		if n > 0 {
			w.maxRRSIGsTry = n
		}
	})
}

// WithWalkerMaxAlgorithms caps the number of distinct DNSSEC
// algorithms a single zone may advertise (DAU bomb guard). Default
// 4.
func WithWalkerMaxAlgorithms(n int) WalkerOption {
	return walkerOptionFunc(func(w *walker) {
		if n > 0 {
			w.maxAlgs = n
		}
	})
}

// WithWalkerMaxKeysPerZone caps the number of usable DNSKEYs
// (post-protocol / post-revoke filter) the walker will accept from
// any single zone. Default 16. The cap defends against KeyTrap-style
// amplification (CVE-2023-50387): a zone publishing many DNSKEYs
// that share a keytag would otherwise drive maxRRSIGsTry × N
// candidate Verify calls per signed RRset.
func WithWalkerMaxKeysPerZone(n int) WalkerOption {
	return walkerOptionFunc(func(w *walker) {
		if n > 0 {
			w.maxKeys = n
		}
	})
}
