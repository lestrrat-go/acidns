package validatorbb

import (
	"time"

	"github.com/lestrrat-go/acidns/wire/rdata"
)

// RRSIGValidNowWithSkew reports whether sig's [SignatureInception,
// SignatureExpiration] window contains now, after expanding the window
// by skew on each side. A zero skew is exact bound checking.
//
// RFC 4034 §3.1.5 specifies the inception/expiration fields as 32-bit
// unsigned seconds-since-epoch, interpreted under RFC 1982 serial-number
// arithmetic (mod 2³²). Naive [time.Time] comparison wraps incorrectly
// past 2106-02-07 — the same code that says "now is before expiration"
// today flips to "now is after expiration" once the wire field rolls
// over. This function performs the comparison on the raw uint32 fields
// using int32 wraparound subtraction, which is the canonical RFC 1982
// `s32lt` predicate.
//
// skew is expressed as a [time.Duration] for ergonomics; values larger
// than a few hours are pathological and silently clamped to one day.
func RRSIGValidNowWithSkew(sig rdata.RRSIG, now time.Time, skew time.Duration) bool {
	if skew < 0 {
		skew = -skew
	}
	if skew > 24*time.Hour {
		skew = 24 * time.Hour
	}
	nowU := uint32(now.Unix())
	skewU := uint32(skew / time.Second)
	incep := sig.SignatureInceptionRaw()
	exp := sig.SignatureExpirationRaw()
	if serialLT(nowU+skewU, incep) {
		return false
	}
	if serialLT(exp, nowU-skewU) {
		return false
	}
	return true
}

// serialLT is the RFC 1982 §3.2 32-bit serial-number "less than"
// predicate. It returns true iff a < b under mod-2³² arithmetic. The
// signed wraparound subtraction (`int32(a-b) < 0`) is the canonical
// implementation: it correctly answers "smaller in serial space" for
// any pair whose distance is below 2³¹, and gives a defined (if
// unspecified by the RFC) answer at the half-window boundary.
func serialLT(a, b uint32) bool { return int32(a-b) < 0 }
