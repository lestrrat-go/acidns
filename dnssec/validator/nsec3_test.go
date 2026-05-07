package validator

import (
	"strings"
	"testing"

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
				strings.ToLower(base32hexEncode(got)))
		})
	}
}

func TestNSEC3IterationCap(t *testing.T) {
	t.Parallel()
	n := wire.MustParseName("example.")
	require.Nil(t, nsec3Hash(n, nil, MaxNSEC3Iterations+1))
}

func TestBase32HexRoundTrip(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM", "0123456789ABCDEFGHIJKLMNOPQRSTUV"} {
		raw, err := base32hexDecode(s)
		require.NoError(t, err)
		require.Equal(t, s, base32hexEncode(raw))
	}
}

func TestHashIntervalContains(t *testing.T) {
	t.Parallel()
	// Non-wraparound: [10, 20] contains 15 but not 25.
	require.True(t, hashIntervalContains([]byte{10}, []byte{20}, []byte{15}))
	require.False(t, hashIntervalContains([]byte{10}, []byte{20}, []byte{25}))
	// Wraparound: [240, 10] contains 250 and 5 but not 100.
	require.True(t, hashIntervalContains([]byte{240}, []byte{10}, []byte{250}))
	require.True(t, hashIntervalContains([]byte{240}, []byte{10}, []byte{5}))
	require.False(t, hashIntervalContains([]byte{240}, []byte{10}, []byte{100}))
	// Endpoints are NOT included (strictly between).
	require.False(t, hashIntervalContains([]byte{10}, []byte{20}, []byte{10}))
	require.False(t, hashIntervalContains([]byte{10}, []byte{20}, []byte{20}))
}
