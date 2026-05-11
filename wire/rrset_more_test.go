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

func TestRRsetAccessors(t *testing.T) {
	t.Parallel()
	name := wirebb.MustParse("a.example.com")
	ar, err := rdata.NewA(netip.MustParseAddr("192.0.2.1"))
	require.NoError(t, err)
	rec := wire.NewRecord(name, 60*time.Second, ar)
	s, err := wire.NewRRset(rec)
	require.NoError(t, err)
	require.True(t, s.Name().Equal(name))
	require.Equal(t, rrtype.ClassIN, s.Class())
	require.Equal(t, rrtype.A, s.Type())
	require.Equal(t, 60*time.Second, s.TTL())
	require.Equal(t, 1, s.Len())
}

func TestNewRRsetEmpty(t *testing.T) {
	t.Parallel()
	_, err := wire.NewRRset()
	require.Error(t, err)
}

func TestNewRRsetClassMismatch(t *testing.T) {
	t.Parallel()
	ar2, err := rdata.NewA(netip.MustParseAddr("192.0.2.1"))
	require.NoError(t, err)
	rec1 := wire.NewRecord(wirebb.MustParse("a.example.com"), time.Hour,
		ar2)
	ar3, err := rdata.NewA(netip.MustParseAddr("192.0.2.2"))
	require.NoError(t, err)
	rec2 := wire.NewRecordClass(wirebb.MustParse("a.example.com"), rrtype.ClassCH, time.Hour,
		ar3)
	_, err = wire.NewRRset(rec1, rec2)
	require.Error(t, err)
}

func TestNewRRsetFromRDatasMismatched(t *testing.T) {
	t.Parallel()
	aaaa, err := rdata.NewAAAA(netip.MustParseAddr("2001:db8::1"))
	require.NoError(t, err)
	ar4, err := rdata.NewA(netip.MustParseAddr("192.0.2.1"))
	require.NoError(t, err)
	_, err = wire.NewRRsetFromRDatas(
		wirebb.MustParse("a.example.com"), rrtype.ClassIN, time.Hour,
		ar4,
		aaaa,
	)
	require.Error(t, err)
}

func TestNewRRsetFromRDatasEmpty(t *testing.T) {
	t.Parallel()
	_, err := wire.NewRRsetFromRDatas(wirebb.MustParse("a.example.com"), rrtype.ClassIN, time.Hour)
	require.Error(t, err)
}
