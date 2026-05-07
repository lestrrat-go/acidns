package validator

import (
	"github.com/lestrrat-go/acidns/dnssec/validator/validatorbb"
	"github.com/lestrrat-go/acidns/wire"
)

// NSEC3HashForTest exposes nsec3Hash for fixture-building tests in the
// validator_test external package.
func NSEC3HashForTest(name wire.Name, salt []byte, iterations uint16) []byte {
	return nsec3Hash(name, salt, iterations)
}

// Base32HexEncodeForTest exposes the validatorbb base32hex encoder under the
// historical name used by fixture tests.
func Base32HexEncodeForTest(b []byte) string { return validatorbb.Base32HexEncode(b) }
