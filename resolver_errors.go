package acidns

import (
	"fmt"

	"github.com/lestrrat-go/acidns/wire"
)

// RCodeError is returned by Resolve when the response carries a non-NoError
// RCODE. The raw Answer remains reachable via Answer() — callers that
// need the response (negative-caching, debug tools, validators) recover it
// with errors.As; callers that just want to branch on the kind of failure use
// errors.Is against the package-level sentinels.
type RCodeError struct {
	code   wire.RCODE
	answer *Answer
}

func NewRCodeError(code wire.RCODE, ans *Answer) *RCodeError {
	return &RCodeError{code: code, answer: ans}
}

// Code returns the response RCODE.
func (e *RCodeError) Code() wire.RCODE { return e.code }

// Answer returns the underlying answer, or nil for sentinel values.
func (e *RCodeError) Answer() *Answer { return e.answer }

func (e *RCodeError) Error() string {
	return fmt.Sprintf("acidns: %s", e.code)
}

// Is matches sentinels by RCODE only — the attached Answer is not part of
// the equality.
func (e *RCodeError) Is(target error) bool {
	t, ok := target.(*RCodeError)
	if !ok {
		return false
	}
	return e.code == t.code
}

// Sentinel RCodeErrors for use with errors.Is. Each carries only the RCODE;
// the Answer is nil. A Resolve call that matches one of these returns
// a fresh RCodeError with both code and answer populated.
var (
	ErrFormErr  = NewRCodeError(wire.RCODEFormErr, nil) //nolint:errname // mirrors RCODE FormErr label
	ErrServFail = NewRCodeError(wire.RCODEServFail, nil)
	ErrNXDOMAIN = NewRCodeError(wire.RCODENXDomain, nil)
	ErrNotImp   = NewRCodeError(wire.RCODENotImp, nil)
	ErrRefused  = NewRCodeError(wire.RCODERefused, nil)
	ErrYXDomain = NewRCodeError(wire.RCODEYXDomain, nil)
	ErrYXRRSet  = NewRCodeError(wire.RCODEYXRRSet, nil)
	ErrNXRRSet  = NewRCodeError(wire.RCODENXRRSet, nil)
	ErrNotAuth  = NewRCodeError(wire.RCODENotAuth, nil)
	ErrNotZone  = NewRCodeError(wire.RCODENotZone, nil)
)
