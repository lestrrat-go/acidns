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

func TestBuilderFullSetters(t *testing.T) {
	t.Parallel()
	rec := dnsmsg.NewRecord(dnsname.MustParse("example.com"), 60*time.Second,
		rdata.NewA(netip.MustParseAddr("192.0.2.1")))
	q := dnsmsg.NewQuestion(dnsname.MustParse("example.com"), rrtype.A)

	m, err := dnsmsg.NewBuilder().
		ID(0xbeef).
		Flags(dnsmsg.Flags(0)).
		Response(true).
		Opcode(dnsmsg.OpcodeUpdate).
		Authoritative(true).
		Truncated(true).
		RecursionDesired(true).
		RecursionAvailable(true).
		AuthenticData(true).
		CheckingDisabled(true).
		RCODE(dnsmsg.RCODENXDomain).
		Question(q).
		Answer(rec).
		Authority(rec).
		Additional(rec).
		Build()
	require.NoError(t, err)
	require.Equal(t, uint16(0xbeef), m.ID())
	require.True(t, m.Flags().Response())
	require.Equal(t, dnsmsg.OpcodeUpdate, m.Flags().Opcode())
	require.True(t, m.Flags().Authoritative())
	require.True(t, m.Flags().Truncated())
	require.True(t, m.Flags().RecursionDesired())
	require.True(t, m.Flags().RecursionAvailable())
	require.True(t, m.Flags().AuthenticData())
	require.True(t, m.Flags().CheckingDisabled())
	require.Equal(t, dnsmsg.RCODENXDomain, m.Flags().RCODE())
	require.Len(t, m.Authorities(), 1)
	require.Len(t, m.Additionals(), 1)
}

func TestBuilderEDNS(t *testing.T) {
	t.Parallel()
	e := dnsmsg.NewEDNSBuilder().UDPSize(4096).DO(true).Build()
	q := dnsmsg.NewQuestion(dnsname.MustParse("example.com"), rrtype.A)
	m, err := dnsmsg.NewBuilder().ID(1).Question(q).EDNS(e).Build()
	require.NoError(t, err)
	got, ok := m.EDNS()
	require.True(t, ok)
	require.True(t, got.DO())
}

func TestNewQuestionClass(t *testing.T) {
	t.Parallel()
	q := dnsmsg.NewQuestionClass(dnsname.MustParse("example."), rrtype.TXT, rrtype.ClassCH)
	require.Equal(t, rrtype.ClassCH, q.Class())
	require.Equal(t, rrtype.TXT, q.Type())
}

func TestRCODEStrings(t *testing.T) {
	t.Parallel()
	cases := []struct {
		rc   dnsmsg.RCODE
		want string
	}{
		{dnsmsg.RCODENoError, "NOERROR"},
		{dnsmsg.RCODEFormErr, "FORMERR"},
		{dnsmsg.RCODEServFail, "SERVFAIL"},
		{dnsmsg.RCODENXDomain, "NXDOMAIN"},
		{dnsmsg.RCODENotImp, "NOTIMP"},
		{dnsmsg.RCODERefused, "REFUSED"},
	}
	for _, c := range cases {
		require.Equal(t, c.want, c.rc.String())
	}
}

func TestOpcodeString(t *testing.T) {
	t.Parallel()
	require.Equal(t, "QUERY", dnsmsg.OpcodeQuery.String())
	require.Equal(t, "UPDATE", dnsmsg.OpcodeUpdate.String())
	require.Equal(t, "NOTIFY", dnsmsg.OpcodeNotify.String())
}

func TestFlagsRoundTrip(t *testing.T) {
	t.Parallel()
	var f dnsmsg.Flags
	f = f.WithResponse(true).
		WithAuthoritative(true).
		WithTruncated(true).
		WithRecursionDesired(true).
		WithRecursionAvailable(true).
		WithAuthenticData(true).
		WithCheckingDisabled(true).
		WithOpcode(dnsmsg.OpcodeNotify).
		WithRCODE(dnsmsg.RCODERefused)
	require.True(t, f.Response())
	require.True(t, f.Authoritative())
	require.True(t, f.Truncated())
	require.True(t, f.RecursionDesired())
	require.True(t, f.RecursionAvailable())
	require.True(t, f.AuthenticData())
	require.True(t, f.CheckingDisabled())
	require.Equal(t, dnsmsg.OpcodeNotify, f.Opcode())
	require.Equal(t, dnsmsg.RCODERefused, f.RCODE())
}
