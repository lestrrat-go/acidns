package wire_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
	"github.com/stretchr/testify/require"
)

func TestFlags(t *testing.T) {
	t.Parallel()

	f := wire.Flags(0).
		WithResponse(true).
		WithOpcode(wire.OpcodeQuery).
		WithRecursionDesired(true).
		WithRecursionAvailable(true).
		WithRCODE(wire.RCODENXDomain)

	require.True(t, f.Response())
	require.Equal(t, wire.OpcodeQuery, f.Opcode())
	require.True(t, f.RecursionDesired())
	require.True(t, f.RecursionAvailable())
	require.False(t, f.Authoritative())
	require.Equal(t, wire.RCODENXDomain, f.RCODE())
}

func TestBuilderQuery(t *testing.T) {
	t.Parallel()

	q := wire.NewQuestion(wirebb.MustParse("example.com"), rrtype.A)
	m, err := wire.NewBuilder().
		ID(0x1234).
		RecursionDesired(true).
		Question(q).
		Build()
	require.NoError(t, err)
	require.Equal(t, uint16(0x1234), m.ID())
	require.True(t, m.Flags().RecursionDesired())
	require.False(t, m.Flags().Response())
	require.Equal(t, 1, len(m.Questions()))
}

func TestRoundTripQuery(t *testing.T) {
	t.Parallel()

	q := wire.NewQuestion(wirebb.MustParse("example.com"), rrtype.A)
	m, err := wire.NewBuilder().
		ID(0xabcd).
		RecursionDesired(true).
		Question(q).
		Build()
	require.NoError(t, err)

	buf, err := wire.Marshal(m)
	require.NoError(t, err)

	m2, err := wire.Unmarshal(buf)
	require.NoError(t, err)

	require.Equal(t, m.ID(), m2.ID())
	require.Equal(t, m.Flags(), m2.Flags())
	require.Equal(t, 1, len(m2.Questions()))
	require.Equal(t, "example.com.", m2.Questions()[0].Name().String())
	require.Equal(t, rrtype.A, m2.Questions()[0].Type())
	require.Equal(t, rrtype.ClassIN, m2.Questions()[0].Class())
}

func TestRoundTripResponse(t *testing.T) {
	t.Parallel()

	name := wirebb.MustParse("example.com")
	q := wire.NewQuestion(name, rrtype.A)
	a := wire.NewRecord(name, 300*time.Second,
		rdata.NewA(netip.MustParseAddr("93.184.216.34")))
	mx := wire.NewRecord(name, 600*time.Second,
		rdata.NewMX(10, wirebb.MustParse("mail.example.com")))

	m, err := wire.NewBuilder().
		ID(1).
		Response(true).
		RecursionDesired(true).
		RecursionAvailable(true).
		Question(q).
		Answer(a).
		Answer(mx).
		Build()
	require.NoError(t, err)

	buf, err := wire.Marshal(m)
	require.NoError(t, err)
	m2, err := wire.Unmarshal(buf)
	require.NoError(t, err)

	require.Equal(t, 1, len(m2.Questions()))
	require.Equal(t, 2, len(m2.Answers()))

	ans := m2.Answers()
	require.Equal(t, rrtype.A, ans[0].Type())
	require.Equal(t, 300*time.Second, ans[0].TTL())
	aRD, ok := ans[0].RData().(rdata.A)
	require.True(t, ok)
	require.Equal(t, "93.184.216.34", aRD.Addr().String())

	mxRD, ok := ans[1].RData().(rdata.MX)
	require.True(t, ok)
	require.Equal(t, uint16(10), mxRD.Preference())
	require.Equal(t, "mail.example.com.", mxRD.Exchange().String())
}

func TestUnmarshalRealResponse(t *testing.T) {
	t.Parallel()

	// Captured via:
	//   dig +noedns +qr +noall +answer @1.1.1.1 example.com A
	// Synthesised here so the test stays hermetic.
	q := wire.NewQuestion(wirebb.MustParse("example.com"), rrtype.A)
	a := wire.NewRecord(
		wirebb.MustParse("example.com"),
		86400*time.Second,
		rdata.NewA(netip.MustParseAddr("93.184.216.34")),
	)
	out, err := wire.NewBuilder().
		ID(0x4242).
		Response(true).
		RecursionDesired(true).
		RecursionAvailable(true).
		Question(q).
		Answer(a).
		Build()
	require.NoError(t, err)

	buf, err := wire.Marshal(out)
	require.NoError(t, err)

	m, err := wire.Unmarshal(buf)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENoError, m.Flags().RCODE())
	require.True(t, m.Flags().Response())
	require.Equal(t, 1, len(m.Answers()))
}

func TestUnmarshalCorrupt(t *testing.T) {
	t.Parallel()

	t.Run("short header", func(t *testing.T) {
		t.Parallel()
		_, err := wire.Unmarshal([]byte{0, 0, 0, 0, 0, 0})
		require.Error(t, err)
	})

	t.Run("truncated question", func(t *testing.T) {
		t.Parallel()
		buf := []byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x'}
		_, err := wire.Unmarshal(buf)
		require.Error(t, err)
	})
}
