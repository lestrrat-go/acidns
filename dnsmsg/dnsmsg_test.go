package dnsmsg_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/stretchr/testify/require"
)

func TestFlags(t *testing.T) {
	t.Parallel()

	f := dnsmsg.Flags(0).
		WithResponse(true).
		WithOpcode(dnsmsg.OpcodeQuery).
		WithRecursionDesired(true).
		WithRecursionAvailable(true).
		WithRCODE(dnsmsg.RCODENXDomain)

	require.True(t, f.Response())
	require.Equal(t, dnsmsg.OpcodeQuery, f.Opcode())
	require.True(t, f.RecursionDesired())
	require.True(t, f.RecursionAvailable())
	require.False(t, f.Authoritative())
	require.Equal(t, dnsmsg.RCODENXDomain, f.RCODE())
}

func TestBuilderQuery(t *testing.T) {
	t.Parallel()

	q := dnsmsg.NewQuestion(dnsname.MustParse("example.com"), rrtype.A)
	m, err := dnsmsg.NewBuilder().
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

	q := dnsmsg.NewQuestion(dnsname.MustParse("example.com"), rrtype.A)
	m, err := dnsmsg.NewBuilder().
		ID(0xabcd).
		RecursionDesired(true).
		Question(q).
		Build()
	require.NoError(t, err)

	buf, err := dnsmsg.Marshal(m)
	require.NoError(t, err)

	m2, err := dnsmsg.Unmarshal(buf)
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

	name := dnsname.MustParse("example.com")
	q := dnsmsg.NewQuestion(name, rrtype.A)
	a := dnsmsg.NewRecord(name, 300*time.Second,
		rdata.NewA(netip.MustParseAddr("93.184.216.34")))
	mx := dnsmsg.NewRecord(name, 600*time.Second,
		rdata.NewMX(10, dnsname.MustParse("mail.example.com")))

	m, err := dnsmsg.NewBuilder().
		ID(1).
		Response(true).
		RecursionDesired(true).
		RecursionAvailable(true).
		Question(q).
		Answer(a).
		Answer(mx).
		Build()
	require.NoError(t, err)

	buf, err := dnsmsg.Marshal(m)
	require.NoError(t, err)
	m2, err := dnsmsg.Unmarshal(buf)
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
	q := dnsmsg.NewQuestion(dnsname.MustParse("example.com"), rrtype.A)
	a := dnsmsg.NewRecord(
		dnsname.MustParse("example.com"),
		86400*time.Second,
		rdata.NewA(netip.MustParseAddr("93.184.216.34")),
	)
	out, err := dnsmsg.NewBuilder().
		ID(0x4242).
		Response(true).
		RecursionDesired(true).
		RecursionAvailable(true).
		Question(q).
		Answer(a).
		Build()
	require.NoError(t, err)

	buf, err := dnsmsg.Marshal(out)
	require.NoError(t, err)

	m, err := dnsmsg.Unmarshal(buf)
	require.NoError(t, err)
	require.Equal(t, dnsmsg.RCODENoError, m.Flags().RCODE())
	require.True(t, m.Flags().Response())
	require.Equal(t, 1, len(m.Answers()))
}

func TestUnmarshalCorrupt(t *testing.T) {
	t.Parallel()

	t.Run("short header", func(t *testing.T) {
		_, err := dnsmsg.Unmarshal([]byte{0, 0, 0, 0, 0, 0})
		require.Error(t, err)
	})

	t.Run("truncated question", func(t *testing.T) {
		buf := []byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x'}
		_, err := dnsmsg.Unmarshal(buf)
		require.Error(t, err)
	})
}
