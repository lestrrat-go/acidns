package rdata_test

import (
	"errors"
	"testing"

	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// TestDNSKEYUnpackRejectsBadProtocol covers SEC-RD-1: RFC 4034 §2.1.2
// mandates the DNSKEY protocol byte is 3. Before this check the wire
// decoder accepted anything; the constructor already rejected.
func TestDNSKEYUnpackRejectsBadProtocol(t *testing.T) {
	t.Parallel()
	// flags=257, protocol=0 (invalid), alg=13 (ECDSAP256SHA256), pubkey=4 bytes
	buf := []byte{
		0x01, 0x01, // flags
		0x00,                   // protocol — RFC mandates 3
		0x0d,                   // algorithm
		0xaa, 0xbb, 0xcc, 0xdd, // pubkey
	}
	unpackErr(t, rrtype.DNSKEY, buf, len(buf))
}

// TestLOCConstructorRejectsBadNibbles covers SEC-RD-3: each of size,
// horizPre, vertPre is mantissa (high nibble) and exponent (low
// nibble), both required to be 0..9 by RFC 1876 §3.
func TestLOCConstructorRejectsBadNibbles(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name                    string
		size, horizPre, vertPre uint8
	}{
		{"size high nibble > 9", 0xa0, 0x12, 0x12},
		{"size low nibble > 9", 0x1a, 0x12, 0x12},
		{"horizPre high nibble > 9", 0x12, 0xff, 0x12},
		{"vertPre low nibble > 9", 0x12, 0x12, 0x0b},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := rdata.NewLOC(0, tc.size, tc.horizPre, tc.vertPre, 0, 0, 0)
			require.Error(t, err)
			require.True(t, errors.Is(err, rdata.ErrInvalidRData),
				"expected ErrInvalidRData, got %v", err)
		})
	}
}

// TestLOCUnpackRejectsBadNibbles covers SEC-RD-3 on the wire side.
func TestLOCUnpackRejectsBadNibbles(t *testing.T) {
	t.Parallel()
	// version=0, size=0xfa (both nibbles out of range), then valid
	// horizPre/vertPre and dummy lat/lon/alt.
	buf := []byte{
		0x00,       // version
		0xfa,       // size — invalid (15/10)
		0x12, 0x13, // horizPre, vertPre
		0x00, 0x00, 0x00, 0x00, // lat
		0x00, 0x00, 0x00, 0x00, // lon
		0x00, 0x00, 0x00, 0x00, // alt
	}
	unpackErr(t, rrtype.LOC, buf, len(buf))
}

// TestZONEMDConstructorRejectsWrongDigestLength covers SEC-RD-5:
// RFC 8976 §4 fixes SHA-384 → 48 bytes and SHA-512 → 64 bytes.
func TestZONEMDConstructorRejectsWrongDigestLength(t *testing.T) {
	t.Parallel()

	t.Run("SHA-384 with short digest", func(t *testing.T) {
		t.Parallel()
		_, err := rdata.NewZONEMD(1, rdata.ZONEMDSchemeSimple, rdata.ZONEMDHashSHA384, make([]byte, 47))
		require.Error(t, err)
		require.True(t, errors.Is(err, rdata.ErrInvalidRData))
	})

	t.Run("SHA-512 with wrong-length digest", func(t *testing.T) {
		t.Parallel()
		_, err := rdata.NewZONEMD(1, rdata.ZONEMDSchemeSimple, rdata.ZONEMDHashSHA512, make([]byte, 48))
		require.Error(t, err)
		require.True(t, errors.Is(err, rdata.ErrInvalidRData))
	})

	t.Run("unknown hash algorithm passes through", func(t *testing.T) {
		t.Parallel()
		// RFC 8976 §3 says ignore unknown algorithms rather than reject —
		// the parse step must preserve them for caller inspection.
		_, err := rdata.NewZONEMD(1, rdata.ZONEMDSchemeSimple, rdata.ZONEMDHashAlgorithm(99), []byte{0xff})
		require.NoError(t, err)
	})
}

// TestZONEMDUnpackRejectsWrongDigestLength covers SEC-RD-5 on the wire side.
func TestZONEMDUnpackRejectsWrongDigestLength(t *testing.T) {
	t.Parallel()
	// serial(4) + scheme=1 + hash=1 (SHA-384) + 5-byte digest (should be 48).
	buf := []byte{
		0x00, 0x00, 0x00, 0x01, // serial
		0x01,                         // scheme = Simple
		0x01,                         // hash = SHA-384
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, // 5-byte digest — should be 48
	}
	unpackErr(t, rrtype.ZONEMD, buf, len(buf))
}
