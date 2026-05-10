package wiretest_test

import (
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wiretest"
	"github.com/stretchr/testify/require"
)

func TestQuery_RoundTrip(t *testing.T) {
	t.Parallel()
	name := wire.MustParseName("example.com")
	q := wiretest.Query(name, rrtype.A)
	require.True(t, q.Flags().RecursionDesired())
	require.False(t, q.Flags().Response())
	require.Len(t, q.Questions(), 1)
	require.Equal(t, name, q.Questions()[0].Name())
	require.Equal(t, rrtype.A, q.Questions()[0].Type())
}

func TestResponse_EchoesQuestion(t *testing.T) {
	t.Parallel()
	name := wire.MustParseName("example.com")
	q := wiretest.Query(name, rrtype.A)
	rec := wiretest.ARecord(name, time.Minute, "192.0.2.1")
	resp := wiretest.Response(q, rec)

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
	q := wiretest.Query(wire.MustParseName("example.com"), rrtype.A)
	resp := wiretest.Authoritative(q)
	require.True(t, resp.Flags().Authoritative())
}

func TestNXDOMAIN(t *testing.T) {
	t.Parallel()
	q := wiretest.Query(wire.MustParseName("nope.example.com"), rrtype.A)
	resp := wiretest.NXDOMAIN(q)
	require.Equal(t, wire.RCODENXDomain, resp.Flags().RCODE())
	require.True(t, resp.Flags().Authoritative())
}

func TestServFail(t *testing.T) {
	t.Parallel()
	q := wiretest.Query(wire.MustParseName("example.com"), rrtype.A)
	resp := wiretest.ServFail(q)
	require.Equal(t, wire.RCODEServFail, resp.Flags().RCODE())
	require.False(t, resp.Flags().Authoritative())
}

func TestRefused(t *testing.T) {
	t.Parallel()
	q := wiretest.Query(wire.MustParseName("example.com"), rrtype.A)
	resp := wiretest.Refused(q)
	require.Equal(t, wire.RCODERefused, resp.Flags().RCODE())
}

func TestEmptyResponse(t *testing.T) {
	t.Parallel()
	resp := wiretest.EmptyResponse()
	require.True(t, resp.Flags().Response())
	require.Empty(t, resp.Questions())
	require.Empty(t, resp.Answers())
}

func TestARecord_RejectsV6(t *testing.T) {
	t.Parallel()
	require.Panics(t, func() {
		wiretest.ARecord(wire.MustParseName("example.com"), time.Minute, "2001:db8::1")
	})
}

func TestAAAARecord_RejectsV4(t *testing.T) {
	t.Parallel()
	require.Panics(t, func() {
		wiretest.AAAARecord(wire.MustParseName("example.com"), time.Minute, "192.0.2.1")
	})
}

func TestRecordHelpers(t *testing.T) {
	t.Parallel()
	name := wire.MustParseName("example.com")
	target := wire.MustParseName("alias.example.com")

	cn, ok := wire.RDataAs[rdata.CNAME](wiretest.CNAMERecord(name, time.Minute, target))
	require.True(t, ok)
	require.Equal(t, target, cn.Target())

	ns, ok := wire.RDataAs[rdata.NS](wiretest.NSRecord(name, time.Minute, target))
	require.True(t, ok)
	require.Equal(t, target, ns.Target())

	mx, ok := wire.RDataAs[rdata.MX](wiretest.MXRecord(name, time.Minute, 10, target))
	require.True(t, ok)
	require.Equal(t, uint16(10), mx.Preference())
	require.Equal(t, target, mx.Exchange())

	txt, ok := wire.RDataAs[rdata.TXT](wiretest.TXTRecord(name, time.Minute, "hello"))
	require.True(t, ok)
	require.Equal(t, []string{"hello"}, txt.Strings())

	soa, ok := wire.RDataAs[rdata.SOA](wiretest.SOARecord(name, time.Minute,
		wire.MustParseName("ns.example.com"),
		wire.MustParseName("admin.example.com"),
		1, time.Hour, 15*time.Minute, 7*24*time.Hour, time.Hour))
	require.True(t, ok)
	require.Equal(t, uint32(1), soa.Serial())
}
