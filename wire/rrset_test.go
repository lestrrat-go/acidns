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
	a1 := wire.NewRecord(name, 60*time.Second, rdata.MustNewA(netip.MustParseAddr("192.0.2.1")))
	a2 := wire.NewRecord(name, 30*time.Second, rdata.MustNewA(netip.MustParseAddr("192.0.2.2")))

	s, err := wire.NewRRset(a1, a2)
	require.NoError(t, err)
	require.Equal(t, rrtype.A, s.Type())
	require.Equal(t, 30*time.Second, s.TTL(), "TTL harmonised to minimum per RFC 2181 §5.2")
	require.Len(t, s.Records(), 2)
}

func TestRRsetMixedTypeRejected(t *testing.T) {
	t.Parallel()
	name := wirebb.MustParse("example.com")
	a := wire.NewRecord(name, 60*time.Second, rdata.MustNewA(netip.MustParseAddr("192.0.2.1")))
	aaaa := wire.NewRecord(name, 60*time.Second, rdata.MustNewAAAA(netip.MustParseAddr("2001:db8::1")))
	_, err := wire.NewRRset(a, aaaa)
	require.Error(t, err)
}

func TestNewRRsetFromRDatas(t *testing.T) {
	t.Parallel()
	s, err := wire.NewRRsetFromRDatas(
		wirebb.MustParse("ns.example.com"),
		rrtype.ClassIN, 3600*time.Second,
		rdata.MustNewA(netip.MustParseAddr("192.0.2.1")),
		rdata.MustNewA(netip.MustParseAddr("192.0.2.2")),
	)
	require.NoError(t, err)
	require.Equal(t, 2, s.Len())
	require.Equal(t, rrtype.A, s.Type())
}

func TestGroupRecords(t *testing.T) {
	t.Parallel()
	name := wirebb.MustParse("example.com")
	a := wire.NewRecord(name, 60*time.Second, rdata.MustNewA(netip.MustParseAddr("192.0.2.1")))
	aaaa := wire.NewRecord(name, 60*time.Second, rdata.MustNewAAAA(netip.MustParseAddr("2001:db8::1")))
	a2 := wire.NewRecord(name, 60*time.Second, rdata.MustNewA(netip.MustParseAddr("192.0.2.2")))

	groups, err := wire.GroupRecords([]wire.Record{a, aaaa, a2})
	require.NoError(t, err)
	require.Len(t, groups, 2)
	require.Equal(t, rrtype.A, groups[0].Type())
	require.Equal(t, 2, groups[0].Len())
	require.Equal(t, rrtype.AAAA, groups[1].Type())
	require.Equal(t, 1, groups[1].Len())
}
