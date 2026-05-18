package dnssecbb_test

import (
	"testing"

	"github.com/lestrrat-go/acidns/dnssec/dnssecbb"
	"github.com/stretchr/testify/require"
)

// TestParseRSAPublicRejectsShortModulus verifies the safe default
// floor on RSA modulus length. Sub-1024-bit keys cannot resist
// contemporary factoring (RFC 8624 §3.1) so the validator refuses
// to instantiate them.
func TestParseRSAPublicRejectsShortModulus(t *testing.T) {
	t.Parallel()

	// RFC 3110 wire form: 1-byte explen, exponent, modulus.
	// 3-byte exponent (0x010001 = 65537) followed by an undersized
	// modulus of 64 bytes (= 512 bits).
	buf := make([]byte, 0, 1+3+64)
	buf = append(buf, 3)                // explen
	buf = append(buf, 0x01, 0x00, 0x01) // e = 65537
	buf = append(buf, make([]byte, 64)...)
	buf[1+3] = 0xC0 // ensure modulus high bit set so length is exact

	_, err := dnssecbb.ParseRSAPublic(buf)
	require.Error(t, err, "ParseRSAPublic must reject sub-1024-bit modulus")
	require.Contains(t, err.Error(), "below floor")
}

// TestParseRSAPublicAcceptsAtFloor confirms a 1024-bit modulus
// (128 bytes) is admitted — the floor is inclusive.
func TestParseRSAPublicAcceptsAtFloor(t *testing.T) {
	t.Parallel()
	buf := make([]byte, 0, 1+3+128)
	buf = append(buf, 3)
	buf = append(buf, 0x01, 0x00, 0x01)
	buf = append(buf, make([]byte, 128)...)
	buf[1+3] = 0xC0

	_, err := dnssecbb.ParseRSAPublic(buf)
	require.NoError(t, err)
}
