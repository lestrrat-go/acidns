package wire_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// TestBuilderBuildSingleShot verifies the single-shot contract:
// MessageBuilder.Build resets the builder to the zero state, so a
// subsequent setter call starts a fresh build (it does NOT extend
// the previously-built Message). The previously-built Message's
// section slices remain intact and independent of post-Build builder
// activity because the reset zeroes b's slice fields, leaving the
// previously-built Message holding the only reference to the old
// backing array.
func TestBuilderBuildSingleShot(t *testing.T) {
	t.Parallel()
	ar, err := rdata.NewA(netip.MustParseAddr("192.0.2.1"))
	require.NoError(t, err)
	b := wire.NewMessageBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("a.test."), rrtype.A)).
		Answer(wire.NewRecord(
			wire.MustParseName("a.test."), time.Hour,
			ar))

	first, err := b.Build()
	require.NoError(t, err)
	require.Equal(t, 1, len(first.Answers()))

	// After Build the builder is reset. A subsequent setter call
	// starts a fresh build; the previously-built Message is untouched.
	ar2, err := rdata.NewA(netip.MustParseAddr("192.0.2.2"))
	require.NoError(t, err)
	b = b.Answer(wire.NewRecord(
		wire.MustParseName("a.test."), time.Hour,
		ar2))

	require.Equal(t, 1, len(first.Answers()),
		"first message must not see post-Build appends")

	second, err := b.Build()
	require.NoError(t, err)
	require.Equal(t, 1, len(second.Answers()),
		"second build is fresh (post-reset) — only the post-reset Answer")
}
