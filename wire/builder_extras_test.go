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

func TestBuilderFullSetters(t *testing.T) {
	t.Parallel()
	rec := wire.NewRecord(wirebb.MustParse("example.com"), 60*time.Second,
		rdata.NewA(netip.MustParseAddr("192.0.2.1")))
	q := wire.NewQuestion(wirebb.MustParse("example.com"), rrtype.A)

	m, err := wire.NewBuilder().
		ID(0xbeef).
		Flags(wire.Flags(0)).
		Response(true).
		Opcode(wire.OpcodeUpdate).
		Authoritative(true).
		Truncated(true).
		RecursionDesired(true).
		RecursionAvailable(true).
		AuthenticData(true).
		CheckingDisabled(true).
		RCODE(wire.RCODENXDomain).
		Question(q).
		Answer(rec).
		Authority(rec).
		Additional(rec).
		Build()
	require.NoError(t, err)
	require.Equal(t, uint16(0xbeef), m.ID())
	require.True(t, m.Flags().Response())
	require.Equal(t, wire.OpcodeUpdate, m.Flags().Opcode())
	require.True(t, m.Flags().Authoritative())
	require.True(t, m.Flags().Truncated())
	require.True(t, m.Flags().RecursionDesired())
	require.True(t, m.Flags().RecursionAvailable())
	require.True(t, m.Flags().AuthenticData())
	require.True(t, m.Flags().CheckingDisabled())
	require.Equal(t, wire.RCODENXDomain, m.Flags().RCODE())
	require.Len(t, m.Authorities(), 1)
	require.Len(t, m.Additionals(), 1)
}

func TestBuilderEDNS(t *testing.T) {
	t.Parallel()
	e := mustEDNS(t, wire.NewEDNSBuilder().UDPSize(4096).DO(true))
	q := wire.NewQuestion(wirebb.MustParse("example.com"), rrtype.A)
	m, err := wire.NewBuilder().ID(1).Question(q).EDNS(e).Build()
	require.NoError(t, err)
	got, ok := m.EDNS()
	require.True(t, ok)
	require.True(t, got.DO())
}

func TestNewQuestionClass(t *testing.T) {
	t.Parallel()
	q := wire.NewQuestionClass(wirebb.MustParse("example."), rrtype.TXT, rrtype.ClassCH)
	require.Equal(t, rrtype.ClassCH, q.Class())
	require.Equal(t, rrtype.TXT, q.Type())
}

func TestRCODEStrings(t *testing.T) {
	t.Parallel()
	cases := []struct {
		rc   wire.RCODE
		want string
	}{
		{wire.RCODENoError, "NOERROR"},
		{wire.RCODEFormErr, "FORMERR"},
		{wire.RCODEServFail, "SERVFAIL"},
		{wire.RCODENXDomain, "NXDOMAIN"},
		{wire.RCODENotImp, "NOTIMP"},
		{wire.RCODERefused, "REFUSED"},
	}
	for _, c := range cases {
		require.Equal(t, c.want, c.rc.String())
	}
}

func TestOpcodeString(t *testing.T) {
	t.Parallel()
	require.Equal(t, "QUERY", wire.OpcodeQuery.String())
	require.Equal(t, "UPDATE", wire.OpcodeUpdate.String())
	require.Equal(t, "NOTIFY", wire.OpcodeNotify.String())
}

func TestFlagsRoundTrip(t *testing.T) {
	t.Parallel()
	var f wire.Flags
	f = f.WithResponse(true).
		WithAuthoritative(true).
		WithTruncated(true).
		WithRecursionDesired(true).
		WithRecursionAvailable(true).
		WithAuthenticData(true).
		WithCheckingDisabled(true).
		WithOpcode(wire.OpcodeNotify).
		WithRCODE(wire.RCODERefused)
	require.True(t, f.Response())
	require.True(t, f.Authoritative())
	require.True(t, f.Truncated())
	require.True(t, f.RecursionDesired())
	require.True(t, f.RecursionAvailable())
	require.True(t, f.AuthenticData())
	require.True(t, f.CheckingDisabled())
	require.Equal(t, wire.OpcodeNotify, f.Opcode())
	require.Equal(t, wire.RCODERefused, f.RCODE())
}
