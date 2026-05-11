package wiretest_test

import (
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/internal/wiretest"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

func TestQuery_RoundTrip(t *testing.T) {
	t.Parallel()
	name := wire.MustParseName("example.com")
	q, err := wiretest.Query(name, rrtype.A)
	require.NoError(t, err)
	require.True(t, q.Flags().RecursionDesired())
	require.False(t, q.Flags().Response())
	require.Len(t, q.Questions(), 1)
	require.Equal(t, name, q.Questions()[0].Name())
	require.Equal(t, rrtype.A, q.Questions()[0].Type())
}

func TestResponse_EchoesQuestion(t *testing.T) {
	t.Parallel()
	name := wire.MustParseName("example.com")
	q, err := wiretest.Query(name, rrtype.A)
	require.NoError(t, err)
	rec, err := wiretest.ARecord(name, time.Minute, "192.0.2.1")
	require.NoError(t, err)
	resp, err := wiretest.Response(q, rec)
	require.NoError(t, err)

	require.True(t, resp.Flags().Response())
	require.False(t, resp.Flags().Authoritative())
	require.Equal(t, q.ID(), resp.ID())
	require.Len(t, resp.Questions(), 1)
	require.Len(t, resp.Answers(), 1)
	a, ok := wire.RDataAs[rdata.A](resp.Answers()[0])
	require.True(t, ok)
	require.Equal(t, "192.0.2.1", a.Addr().String())
}

func TestAuthoritative_SetsAA(t *testing.T) {
	t.Parallel()
	q, err := wiretest.Query(wire.MustParseName("example.com"), rrtype.A)
	require.NoError(t, err)
	resp, err := wiretest.Authoritative(q)
	require.NoError(t, err)
	require.True(t, resp.Flags().Authoritative())
}

func TestNXDOMAIN(t *testing.T) {
	t.Parallel()
	q, err := wiretest.Query(wire.MustParseName("nope.example.com"), rrtype.A)
	require.NoError(t, err)
	resp, err := wiretest.NXDOMAIN(q)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENXDomain, resp.Flags().RCODE())
	require.True(t, resp.Flags().Authoritative())
}

func TestServFail(t *testing.T) {
	t.Parallel()
	q, err := wiretest.Query(wire.MustParseName("example.com"), rrtype.A)
	require.NoError(t, err)
	resp, err := wiretest.ServFail(q)
	require.NoError(t, err)
	require.Equal(t, wire.RCODEServFail, resp.Flags().RCODE())
	require.False(t, resp.Flags().Authoritative())
}

func TestRefused(t *testing.T) {
	t.Parallel()
	q, err := wiretest.Query(wire.MustParseName("example.com"), rrtype.A)
	require.NoError(t, err)
	resp, err := wiretest.Refused(q)
	require.NoError(t, err)
	require.Equal(t, wire.RCODERefused, resp.Flags().RCODE())
}

func TestEmptyResponse(t *testing.T) {
	t.Parallel()
	resp, err := wiretest.EmptyResponse()
	require.NoError(t, err)
	require.True(t, resp.Flags().Response())
	require.Empty(t, resp.Questions())
	require.Empty(t, resp.Answers())
}

func TestARecord_RejectsV6(t *testing.T) {
	t.Parallel()
	_, err := wiretest.ARecord(wire.MustParseName("example.com"), time.Minute, "2001:db8::1")
	require.Error(t, err)
}

func TestAAAARecord_RejectsV4(t *testing.T) {
	t.Parallel()
	_, err := wiretest.AAAARecord(wire.MustParseName("example.com"), time.Minute, "192.0.2.1")
	require.Error(t, err)
}

func TestRecordHelpers(t *testing.T) {
	t.Parallel()
	name := wire.MustParseName("example.com")
	target := wire.MustParseName("alias.example.com")

	cnRec, err := wiretest.CNAMERecord(name, time.Minute, target)
	require.NoError(t, err)
	cn, ok := wire.RDataAs[rdata.CNAME](cnRec)
	require.True(t, ok)
	require.Equal(t, target, cn.Target())

	nsRec, err := wiretest.NSRecord(name, time.Minute, target)
	require.NoError(t, err)
	ns, ok := wire.RDataAs[rdata.NS](nsRec)
	require.True(t, ok)
	require.Equal(t, target, ns.Target())

	mxRec, err := wiretest.MXRecord(name, time.Minute, 10, target)
	require.NoError(t, err)
	mx, ok := wire.RDataAs[rdata.MX](mxRec)
	require.True(t, ok)
	require.Equal(t, uint16(10), mx.Preference())
	require.Equal(t, target, mx.Exchange())

	txtRec, err := wiretest.TXTRecord(name, time.Minute, "hello")
	require.NoError(t, err)
	txt, ok := wire.RDataAs[rdata.TXT](txtRec)
	require.True(t, ok)
	require.Equal(t, []string{"hello"}, txt.Strings())

	soaRec, err := wiretest.SOARecord(name, time.Minute,
		wire.MustParseName("ns.example.com"),
		wire.MustParseName("admin.example.com"),
		1, time.Hour, 15*time.Minute, 7*24*time.Hour, time.Hour)
	require.NoError(t, err)
	soa, ok := wire.RDataAs[rdata.SOA](soaRec)
	require.True(t, ok)
	require.Equal(t, uint32(1), soa.Serial())
}
