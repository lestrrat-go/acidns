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

func TestRRset(t *testing.T) {
	t.Parallel()
	name := wirebb.MustParse("example.com")
	ar, err := rdata.NewA(netip.MustParseAddr("192.0.2.1"))
	require.NoError(t, err)
	a1 := wire.NewRecord(name, 60*time.Second, ar)
	ar2, err := rdata.NewA(netip.MustParseAddr("192.0.2.2"))
	require.NoError(t, err)
	a2 := wire.NewRecord(name, 30*time.Second, ar2)

	s, err := wire.NewRRset(a1, a2)
	require.NoError(t, err)
	require.Equal(t, rrtype.A, s.Type())
	require.Equal(t, 30*time.Second, s.TTL(), "TTL harmonised to minimum per RFC 2181 §5.2")
	require.Len(t, s.Records(), 2)
}

func TestRRsetMixedTypeRejected(t *testing.T) {
	t.Parallel()
	name := wirebb.MustParse("example.com")
	ar3, err := rdata.NewA(netip.MustParseAddr("192.0.2.1"))
	require.NoError(t, err)
	a := wire.NewRecord(name, 60*time.Second, ar3)
	aaaa2, err := rdata.NewAAAA(netip.MustParseAddr("2001:db8::1"))
	require.NoError(t, err)
	aaaa := wire.NewRecord(name, 60*time.Second, aaaa2)
	_, err = wire.NewRRset(a, aaaa)
	require.Error(t, err)
}

func TestNewRRsetFromRDatas(t *testing.T) {
	t.Parallel()
	ar5, err := rdata.NewA(netip.MustParseAddr("192.0.2.2"))
	require.NoError(t, err)
	ar4, err := rdata.NewA(netip.MustParseAddr("192.0.2.1"))
	require.NoError(t, err)
	s, err := wire.NewRRsetFromRDatas(
		wirebb.MustParse("ns.example.com"),
		rrtype.ClassIN, 3600*time.Second,
		ar4,
		ar5,
	)
	require.NoError(t, err)
	require.Equal(t, 2, s.Len())
	require.Equal(t, rrtype.A, s.Type())
}

func TestGroupRecords(t *testing.T) {
	t.Parallel()
	name := wirebb.MustParse("example.com")
	ar6, err := rdata.NewA(netip.MustParseAddr("192.0.2.1"))
	require.NoError(t, err)
	a := wire.NewRecord(name, 60*time.Second, ar6)
	aaaa3, err := rdata.NewAAAA(netip.MustParseAddr("2001:db8::1"))
	require.NoError(t, err)
	aaaa := wire.NewRecord(name, 60*time.Second, aaaa3)
	ar7, err := rdata.NewA(netip.MustParseAddr("192.0.2.2"))
	require.NoError(t, err)
	a2 := wire.NewRecord(name, 60*time.Second, ar7)

	groups, err := wire.GroupRecords([]wire.Record{a, aaaa, a2})
	require.NoError(t, err)
	require.Len(t, groups, 2)
	require.Equal(t, rrtype.A, groups[0].Type())
	require.Equal(t, 2, groups[0].Len())
	require.Equal(t, rrtype.AAAA, groups[1].Type())
	require.Equal(t, 1, groups[1].Len())
}
