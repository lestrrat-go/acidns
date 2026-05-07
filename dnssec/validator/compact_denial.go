package validator

import (
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// IsCompactNXDOMAIN returns true if nsec carries the NXNAME pseudo-type in
// its bitmap, signalling NXDOMAIN under draft-ietf-dnsop-compact-denial-of-
// existence semantics. Compact-denial servers return NOERROR + NODATA with
// a single NSEC; clients (and the validator) infer NXDOMAIN from the
// presence of the NXNAME bit.
//
// This helper does not itself perform validation; it classifies a NSEC
// payload that ValidateRRset has already deemed Secure.
func IsCompactNXDOMAIN(nsec rdata.NSEC) bool {
	for _, t := range nsec.Types() {
		if t == rrtype.NXNAME {
			return true
		}
	}
	return false
}
