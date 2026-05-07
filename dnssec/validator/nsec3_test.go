package validator

import (
	"strings"
	"testing"

	"github.com/lestrrat-go/acidns/dnssec/validator/validatorbb"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/stretchr/testify/require"
)

// RFC 5155 Appendix A example zone uses iterations=12 and salt=AABBCCDD.
// The hashed names are documented in §A.1; we cross-check our hash function
// against three of them.
func TestNSEC3HashRFC5155Appendix(t *testing.T) {
	t.Parallel()
	salt := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	tests := []struct {
		name     string
		expected string
	}{
		{"example.", "0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM"},
		{"a.example.", "35MTHGPGCU1QG68FAB165KLNSNK3DPVL"},
		{"ai.example.", "GJEQE526PLBF1G8MKLP59ENFD789NJGI"},
		{"ns1.example.", "2T7B4G4VSA5SMI47K61MV5BV1A22BOJR"},
		{"x.y.w.example.", "2VPTU5TIMAMQTTGL4LUU9KG21E0AOR3S"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n := wire.MustParseName(tc.name)
			got := nsec3Hash(n, salt, 12)
			require.Equal(t, strings.ToLower(tc.expected),
				strings.ToLower(validatorbb.Base32HexEncode(got)))
		})
	}
}

func TestNSEC3IterationCap(t *testing.T) {
	t.Parallel()
	n := wire.MustParseName("example.")
	require.Nil(t, nsec3Hash(n, nil, MaxNSEC3Iterations+1))
}
