package authoritative

import (
	"testing"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// TestSetRCODESplits12Bit verifies the 12-bit RCODE split across header
// (low 4 bits) and OPT.ExtendedRCODE (high 8 bits). RFC 6891 §6.1.3
// defines this layout so RCODEs like BADCOOKIE (23 = 0x17) survive
// round-trip without silently truncating to RCODE 7 (YXRRSet).
func TestSetRCODESplits12Bit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		fullRCODE wire.RCODE
		wantHdr   wire.RCODE
		wantExt   uint8
	}{
		{"RCODE_NOERROR_0", wire.RCODE(0), wire.RCODE(0), 0},
		{"RCODE_REFUSED_5", wire.RCODE(5), wire.RCODE(5), 0},
		{"RCODE_BADVERS_16", wire.RCODE(16), wire.RCODE(0), 1},
		{"RCODE_BADKEY_17", wire.RCODE(17), wire.RCODE(1), 1},
		{"RCODE_BADTIME_18", wire.RCODE(18), wire.RCODE(2), 1},
		{"RCODE_BADCOOKIE_23", wire.RCODE(23), wire.RCODE(7), 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			q, err := wire.NewMessageBuilder().
				ID(1).
				Question(wire.NewQuestion(wire.MustParseName("test.example"), rrtype.A)).
				EDNS(mustEDNS(t, wire.NewEDNSBuilder().UDPSize(1232))).
				Build()
			require.NoError(t, err)

			b := wire.NewMessageBuilder().
				ID(q.ID()).
				Response(true).
				Question(q.Questions()[0])
			b = setRCODE(b, q, tc.fullRCODE)
			out, err := b.Build()
			require.NoError(t, err)

			require.Equal(t, tc.wantHdr, out.Flags().RCODE(),
				"header RCODE must be the low 4 bits of the requested code")
			e, ok := out.EDNS()
			require.True(t, ok)
			require.Equal(t, tc.wantExt, e.ExtendedRCODE(),
				"OPT.ExtendedRCODE must be the high 8 bits")
		})
	}
}

// TestSetRCODENoEDNSDoesNotAttachOPT confirms that setRCODE behaves
// identically to a header-only RCODE update when the request lacks
// OPT — no spurious OPT is added, even for high-value RCODEs (which
// is the right call: a non-EDNS client cannot consume an extended
// RCODE anyway).
func TestSetRCODENoEDNSDoesNotAttachOPT(t *testing.T) {
	t.Parallel()
	q, err := wire.NewMessageBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("test.example"), rrtype.A)).
		Build()
	require.NoError(t, err)

	b := wire.NewMessageBuilder().ID(q.ID()).Response(true).Question(q.Questions()[0])
	b = setRCODE(b, q, wire.RCODE(23)) // BADCOOKIE
	out, err := b.Build()
	require.NoError(t, err)

	_, ok := out.EDNS()
	require.False(t, ok, "non-EDNS query must not get an OPT")
}
