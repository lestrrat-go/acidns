package wire_test

import (
	"testing"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wiretest"
	"github.com/stretchr/testify/require"
)

func TestPadEncrypted_AlignsTo128(t *testing.T) {
	t.Parallel()
	q := wiretest.Query(wire.MustParseName("example.com"), rrtype.A)
	padded := wire.PadEncrypted(q)
	buf, err := wire.Marshal(padded)
	require.NoError(t, err)
	require.Equal(t, 0, len(buf)%128, "padded length %d is not a multiple of 128", len(buf))

	// EDNS Padding option must be present.
	e, ok := padded.EDNS()
	require.True(t, ok)
	var hasPad bool
	for _, opt := range e.Options() {
		if opt.Code() == wire.EDNSOptionPadding {
			hasPad = true
			break
		}
	}
	require.True(t, hasPad, "padded message must carry EDNS Padding option")
}

func TestPadEncrypted_AlreadyPadded_NoChange(t *testing.T) {
	t.Parallel()
	q := wiretest.Query(wire.MustParseName("example.com"), rrtype.A)

	// Add a 5-byte Padding option ourselves.
	preset, err := wire.NewEDNSOption(wire.EDNSOptionPadding, []byte{0, 0, 0, 0, 0})
	require.NoError(t, err)
	b := wire.NewBuilder().
		ID(q.ID()).
		Flags(q.Flags()).
		Question(q.Questions()[0]).
		EDNS(mustEDNS(t, wire.NewEDNSBuilder().UDPSize(1232).Option(preset)))
	manual, err := b.Build()
	require.NoError(t, err)

	got := wire.PadEncrypted(manual)
	require.Same(t, manual, got, "PadEncrypted must return the original Message when a Padding option is already present")
}

func TestPadEncrypted_NoEDNS_AddsOPT(t *testing.T) {
	t.Parallel()
	// Build a query with NO EDNS.
	bare, err := wire.NewBuilder().
		ID(0xbeef).
		RecursionDesired(true).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	require.NoError(t, err)
	_, hadEDNS := bare.EDNS()
	require.False(t, hadEDNS)

	padded := wire.PadEncrypted(bare)
	e, ok := padded.EDNS()
	require.True(t, ok, "PadEncrypted must add an OPT pseudo-RR to a message without EDNS")
	require.Equal(t, uint16(1232), e.UDPSize())

	buf, err := wire.Marshal(padded)
	require.NoError(t, err)
	require.Equal(t, 0, len(buf)%128)
}

func TestPadEncrypted_PreservesExistingOptions(t *testing.T) {
	t.Parallel()
	q := wire.NewBuilder().
		ID(1).
		RecursionDesired(true).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		EDNS(mustEDNS(t, wire.NewEDNSBuilder().
			UDPSize(4096).
			DO(true).
			Option(wire.NewNSID(nil))))
	msg, err := q.Build()
	require.NoError(t, err)

	padded := wire.PadEncrypted(msg)
	e, ok := padded.EDNS()
	require.True(t, ok)
	require.Equal(t, uint16(4096), e.UDPSize(), "UDPSize must be preserved")
	require.True(t, e.DO(), "DO bit must be preserved")

	codes := make(map[uint16]bool)
	for _, opt := range e.Options() {
		codes[opt.Code()] = true
	}
	require.True(t, codes[wire.EDNSOptionNSID], "NSID option must be preserved")
	require.True(t, codes[wire.EDNSOptionPadding], "Padding option must be added")
}
