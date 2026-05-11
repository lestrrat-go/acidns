package wire_test

import (
	"testing"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
	"github.com/stretchr/testify/require"
)

func TestEDNSBuilder(t *testing.T) {
	t.Parallel()

	o, err := wire.NewEDNSOption(8, []byte{0xab, 0xcd})
	require.NoError(t, err)

	e := mustEDNS(t, wire.NewEDNSBuilder().
		UDPSize(1232).
		DO(true).
		Option(o))
	require.Equal(t, uint16(1232), e.UDPSize())
	require.True(t, e.DO())
	require.Equal(t, uint8(0), e.Version())
	require.Equal(t, 1, len(e.Options()))
	require.Equal(t, uint16(8), e.Options()[0].Code())
}

func TestMessageWithEDNS(t *testing.T) {
	t.Parallel()

	e := mustEDNS(t, wire.NewEDNSBuilder().UDPSize(4096).DO(true))
	q := wire.NewQuestion(wirebb.MustParse("example.com"), rrtype.A)
	m, err := wire.NewMessageBuilder().
		ID(1).
		RecursionDesired(true).
		Question(q).
		EDNS(e).
		Build()
	require.NoError(t, err)

	got, ok := m.EDNS()
	require.True(t, ok)
	require.Equal(t, uint16(4096), got.UDPSize())
	require.True(t, got.DO())
}

func TestEDNSRoundTrip(t *testing.T) {
	t.Parallel()

	cookie, err := wire.NewEDNSOption(10, []byte{1, 2, 3, 4, 5, 6, 7, 8})
	require.NoError(t, err)

	e := mustEDNS(t, wire.NewEDNSBuilder().
		UDPSize(1232).
		DO(true).
		Version(0).
		Option(cookie))
	q := wire.NewQuestion(wirebb.MustParse("example.com"), rrtype.A)
	m, err := wire.NewMessageBuilder().
		ID(0xbeef).
		RecursionDesired(true).
		Question(q).
		EDNS(e).
		Build()
	require.NoError(t, err)

	buf, err := wire.Marshal(m)
	require.NoError(t, err)

	m2, err := wire.Unmarshal(buf)
	require.NoError(t, err)

	got, ok := m2.EDNS()
	require.True(t, ok)
	require.Equal(t, uint16(1232), got.UDPSize())
	require.True(t, got.DO())
	require.Equal(t, 1, len(got.Options()))
	require.Equal(t, uint16(10), got.Options()[0].Code())
	require.Equal(t, []byte{1, 2, 3, 4, 5, 6, 7, 8}, got.Options()[0].Data())

	// OPT must NOT appear in Additionals — it's surfaced via EDNS().
	require.Equal(t, 0, len(m2.Additionals()))
}

func TestEDNSExtendedRCODE(t *testing.T) {
	t.Parallel()
	e := mustEDNS(t, wire.NewEDNSBuilder().
		UDPSize(1232).
		ExtendedRCODE(1)) // upper bits push the effective RCODE > 15
	require.Equal(t, uint8(1), e.ExtendedRCODE())
}

// TestEDNSBuilderSingleShot verifies that EDNSBuilder.Build resets the
// builder so a subsequent Build produces a fresh, independent EDNS
// value without leaking the previous Options slice.
func TestEDNSBuilderSingleShot(t *testing.T) {
	t.Parallel()
	o1, err := wire.NewEDNSOption(8, []byte{0x01})
	require.NoError(t, err)
	b := wire.NewEDNSBuilder().UDPSize(4096).DO(true).Option(o1)

	first, err := b.Build()
	require.NoError(t, err)
	require.Equal(t, uint16(4096), first.UDPSize())
	require.True(t, first.DO())
	require.Equal(t, 1, len(first.Options()))

	// After Build the builder is reset to the constructor's default
	// (UDPSize=1232, no options, DO=false).
	second, err := b.Build()
	require.NoError(t, err)
	require.Equal(t, uint16(1232), second.UDPSize(), "reset must re-seed UDPSize default")
	require.False(t, second.DO(), "reset must clear DO")
	require.Equal(t, 0, len(second.Options()), "reset must clear Options")

	// First build is unaffected.
	require.Equal(t, uint16(4096), first.UDPSize())
	require.Equal(t, 1, len(first.Options()))
}
