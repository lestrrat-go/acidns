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

// TestBuilderBuildSnapshotsAnswers verifies the immutability contract:
// a Message returned by Build must not see records the caller appends
// to the builder afterwards. Without the snapshot, the builder's
// answers slice would alias the message's answers slice and a later
// Builder.Answer call could grow the underlying array in place.
func TestBuilderBuildSnapshotsAnswers(t *testing.T) {
	t.Parallel()
	b := wire.NewBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("a.test."), rrtype.A)).
		Answer(wire.NewRecord(
			wire.MustParseName("a.test."), time.Hour,
			rdata.NewA(netip.MustParseAddr("192.0.2.1"))))

	first, err := b.Build()
	require.NoError(t, err)
	require.Equal(t, 1, len(first.Answers()))

	// Append after Build — must NOT change the previously-built message.
	b = b.Answer(wire.NewRecord(
		wire.MustParseName("a.test."), time.Hour,
		rdata.NewA(netip.MustParseAddr("192.0.2.2"))))

	require.Equal(t, 1, len(first.Answers()),
		"first message must not see post-Build appends")

	second, err := b.Build()
	require.NoError(t, err)
	require.Equal(t, 2, len(second.Answers()))
}
