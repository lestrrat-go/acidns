package validatorbb

import (
	"time"

	"github.com/lestrrat-go/acidns/wire/rdata"
)

// RRSIGValidNowWithSkew reports whether sig's [SignatureInception,
// SignatureExpiration] window contains now, after expanding the window
// by skew on each side. A zero skew is exact bound checking.
//
// RFC 4034 §3.1.5 specifies inclusive inception and expiration, but the
// arithmetic here uses a strict before/after which is equivalent for
// second-resolution timestamps and matches the validator's behaviour.
func RRSIGValidNowWithSkew(sig rdata.RRSIG, now time.Time, skew time.Duration) bool {
	if now.Add(skew).Before(sig.SignatureInception()) {
		return false
	}
	if now.Add(-skew).After(sig.SignatureExpiration()) {
		return false
	}
	return true
}
