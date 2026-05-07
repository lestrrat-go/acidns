package acidns

import (
	"fmt"

	"github.com/lestrrat-go/acidns/wire"
)

// RCodeError is returned by Resolve when the response carries a non-NoError
// RCODE. The raw Answer remains reachable via the Answer field — callers that
// need the response (negative-caching, debug tools, validators) recover it
// with errors.As; callers that just want to branch on the kind of failure use
// errors.Is against the package-level sentinels.
type RCodeError struct {
	Code   wire.RCODE
	Answer Answer
}

func (e *RCodeError) Error() string {
	return fmt.Sprintf("acidns: %s", e.Code)
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
	ErrFormErr  = &RCodeError{Code: wire.RCODEFormErr}
	ErrServFail = &RCodeError{Code: wire.RCODEServFail}
	ErrNXDOMAIN = &RCodeError{Code: wire.RCODENXDomain}
	ErrNotImp   = &RCodeError{Code: wire.RCODENotImp}
	ErrRefused  = &RCodeError{Code: wire.RCODERefused}
	ErrYXDomain = &RCodeError{Code: wire.RCODEYXDomain}
	ErrYXRRSet  = &RCodeError{Code: wire.RCODEYXRRSet}
	ErrNXRRSet  = &RCodeError{Code: wire.RCODENXRRSet}
	ErrNotAuth  = &RCodeError{Code: wire.RCODENotAuth}
	ErrNotZone  = &RCodeError{Code: wire.RCODENotZone}
)
