package validator

import "time"

type walkerOptionFunc func(*walker)

func (f walkerOptionFunc) applyWalker(w *walker) { f(w) }

// WithAnchors configures one or more trust anchors. The walker selects the
// closest covering anchor for each query. If unset, IANARootAnchor() is
// used.
func WithAnchors(anchors ...Anchor) WalkerOption {
	return walkerOptionFunc(func(w *walker) {
		w.anchors = append(w.anchors[:0], anchors...)
	})
}

// WithNTAStore plugs in an existing NTA store. If unset, an empty store is
// allocated. NTAs short-circuit validation for covered names; cf. the
// project's DNSSEC stance.
func WithNTAStore(s *NTAStore) WalkerOption {
	return walkerOptionFunc(func(w *walker) {
		if s != nil {
			w.ntas = s
		}
	})
}

// WithBogusPolicy sets the policy applied when validation fails. Default is
// BogusReturnSERVFAIL (the strict reading of RFC 4035 §5.5).
func WithBogusPolicy(p BogusPolicy) WalkerOption {
	return walkerOptionFunc(func(w *walker) { w.bogusPolicy = p })
}

// WithNow injects a clock. Tests use this to simulate signature inception
// and expiration without sleeping. Default is time.Now.
func WithNow(now func() time.Time) WalkerOption {
	return walkerOptionFunc(func(w *walker) {
		if now != nil {
			w.now = now
		}
	})
}

// WithClockSkew widens the RRSIG inception/expiration window by skew on
// each side. Production deployments typically pick 5–15 minutes; the
// default of 0 is the conservative reading of RFC 4035 §5.3.
func WithClockSkew(skew time.Duration) WalkerOption {
	return walkerOptionFunc(func(w *walker) {
		if skew >= 0 {
			w.skew = skew
		}
	})
}

// WithMaxZoneCuts caps the depth of the chain walk. Default 16 is enough
// for any real qname and prevents zone-cut bombs.
func WithMaxZoneCuts(n int) WalkerOption {
	return walkerOptionFunc(func(w *walker) {
		if n > 0 {
			w.maxZoneCuts = n
		}
	})
}

// WithMaxRRSIGsTry caps the number of RRSIGs verified per RRset. Default 8.
// Without this cap a hostile zone could ship many RRSIGs to amplify CPU
// cost on a verifier.
func WithMaxRRSIGsTry(n int) WalkerOption {
	return walkerOptionFunc(func(w *walker) {
		if n > 0 {
			w.maxRRSIGsTry = n
		}
	})
}

// WithMaxAlgorithms caps the number of distinct DNSSEC algorithms a single
// zone may advertise (DAU bomb guard). Default 4.
func WithMaxAlgorithms(n int) WalkerOption {
	return walkerOptionFunc(func(w *walker) {
		if n > 0 {
			w.maxAlgs = n
		}
	})
}
