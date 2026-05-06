package dnsclient

import (
	"fmt"

	"github.com/lestrrat-go/acidns/dnsmsg"
)

// RCodeError is returned by Resolve when the response carries a non-NoError
// RCODE. The raw Answer remains reachable via the Answer field — callers that
// need the response (negative-caching, debug tools, validators) recover it
// with errors.As; callers that just want to branch on the kind of failure use
// errors.Is against the package-level sentinels.
type RCodeError struct {
	Code   dnsmsg.RCODE
	Answer Answer
}

func (e *RCodeError) Error() string {
	return fmt.Sprintf("dnsclient: %s", e.Code)
}

// Is matches sentinels by RCODE only — the attached Answer is not part of
// the equality.
func (e *RCodeError) Is(target error) bool {
	t, ok := target.(*RCodeError)
	if !ok {
		return false
	}
	return e.Code == t.Code
}

// Sentinel RCodeErrors for use with errors.Is. Each carries only the RCODE;
// the Answer field is nil. A Resolve call that matches one of these returns
// a fresh RCodeError with both Code and Answer populated.
var (
	ErrFormErr   = &RCodeError{Code: dnsmsg.RCODEFormErr}
	ErrServFail  = &RCodeError{Code: dnsmsg.RCODEServFail}
	ErrNXDOMAIN  = &RCodeError{Code: dnsmsg.RCODENXDomain}
	ErrNotImp    = &RCodeError{Code: dnsmsg.RCODENotImp}
	ErrRefused   = &RCodeError{Code: dnsmsg.RCODERefused}
	ErrYXDomain  = &RCodeError{Code: dnsmsg.RCODEYXDomain}
	ErrYXRRSet   = &RCodeError{Code: dnsmsg.RCODEYXRRSet}
	ErrNXRRSet   = &RCodeError{Code: dnsmsg.RCODENXRRSet}
	ErrNotAuth   = &RCodeError{Code: dnsmsg.RCODENotAuth}
	ErrNotZone   = &RCodeError{Code: dnsmsg.RCODENotZone}
)
