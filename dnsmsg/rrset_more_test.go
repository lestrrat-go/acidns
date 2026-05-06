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

func TestRRsetAccessors(t *testing.T) {
	t.Parallel()
	name := dnsname.MustParse("a.example.com")
	rec := dnsmsg.NewRecord(name, 60*time.Second, rdata.NewA(netip.MustParseAddr("192.0.2.1")))
	s, err := dnsmsg.NewRRset(rec)
	require.NoError(t, err)
	require.True(t, s.Name().Equal(name))
	require.Equal(t, rrtype.ClassIN, s.Class())
	require.Equal(t, rrtype.A, s.Type())
	require.Equal(t, 60*time.Second, s.TTL())
	require.Equal(t, 1, s.Len())
}

func TestNewRRsetEmpty(t *testing.T) {
	t.Parallel()
	_, err := dnsmsg.NewRRset()
	require.Error(t, err)
}

func TestNewRRsetClassMismatch(t *testing.T) {
	t.Parallel()
	rec1 := dnsmsg.NewRecord(dnsname.MustParse("a.example.com"), time.Hour,
		rdata.NewA(netip.MustParseAddr("192.0.2.1")))
	rec2 := dnsmsg.NewRecordClass(dnsname.MustParse("a.example.com"), rrtype.ClassCH, time.Hour,
		rdata.NewA(netip.MustParseAddr("192.0.2.2")))
	_, err := dnsmsg.NewRRset(rec1, rec2)
	require.Error(t, err)
}

func TestNewRRsetFromRDatasMismatched(t *testing.T) {
	t.Parallel()
	_, err := dnsmsg.NewRRsetFromRDatas(
		dnsname.MustParse("a.example.com"), rrtype.ClassIN, time.Hour,
		rdata.NewA(netip.MustParseAddr("192.0.2.1")),
		rdata.NewAAAA(netip.MustParseAddr("2001:db8::1")),
	)
	require.Error(t, err)
}

func TestNewRRsetFromRDatasEmpty(t *testing.T) {
	t.Parallel()
	_, err := dnsmsg.NewRRsetFromRDatas(dnsname.MustParse("a.example.com"), rrtype.ClassIN, time.Hour)
	require.Error(t, err)
}
