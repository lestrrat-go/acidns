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

func TestRRset(t *testing.T) {
	t.Parallel()
	name := dnsname.MustParse("example.com")
	a1 := dnsmsg.NewRecord(name, 60*time.Second, rdata.NewA(netip.MustParseAddr("192.0.2.1")))
	a2 := dnsmsg.NewRecord(name, 30*time.Second, rdata.NewA(netip.MustParseAddr("192.0.2.2")))

	s, err := dnsmsg.NewRRset(a1, a2)
	require.NoError(t, err)
	require.Equal(t, rrtype.A, s.Type())
	require.Equal(t, 30*time.Second, s.TTL(), "TTL harmonised to minimum per RFC 2181 §5.2")
	require.Len(t, s.Records(), 2)
}

func TestRRsetMixedTypeRejected(t *testing.T) {
	t.Parallel()
	name := dnsname.MustParse("example.com")
	a := dnsmsg.NewRecord(name, 60*time.Second, rdata.NewA(netip.MustParseAddr("192.0.2.1")))
	aaaa := dnsmsg.NewRecord(name, 60*time.Second, rdata.NewAAAA(netip.MustParseAddr("2001:db8::1")))
	_, err := dnsmsg.NewRRset(a, aaaa)
	require.Error(t, err)
}

func TestNewRRsetFromRDatas(t *testing.T) {
	t.Parallel()
	s, err := dnsmsg.NewRRsetFromRDatas(
		dnsname.MustParse("ns.example.com"),
		rrtype.ClassIN, 3600*time.Second,
		rdata.NewA(netip.MustParseAddr("192.0.2.1")),
		rdata.NewA(netip.MustParseAddr("192.0.2.2")),
	)
	require.NoError(t, err)
	require.Equal(t, 2, s.Len())
	require.Equal(t, rrtype.A, s.Type())
}

func TestGroupRecords(t *testing.T) {
	t.Parallel()
	name := dnsname.MustParse("example.com")
	a := dnsmsg.NewRecord(name, 60*time.Second, rdata.NewA(netip.MustParseAddr("192.0.2.1")))
	aaaa := dnsmsg.NewRecord(name, 60*time.Second, rdata.NewAAAA(netip.MustParseAddr("2001:db8::1")))
	a2 := dnsmsg.NewRecord(name, 60*time.Second, rdata.NewA(netip.MustParseAddr("192.0.2.2")))

	groups, err := dnsmsg.GroupRecords([]dnsmsg.Record{a, aaaa, a2})
	require.NoError(t, err)
	require.Len(t, groups, 2)
	require.Equal(t, rrtype.A, groups[0].Type())
	require.Equal(t, 2, groups[0].Len())
	require.Equal(t, rrtype.AAAA, groups[1].Type())
	require.Equal(t, 1, groups[1].Len())
}
