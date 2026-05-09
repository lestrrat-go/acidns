package rdata_test

import (
	"testing"

	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
	"github.com/stretchr/testify/require"
)

func TestRP(t *testing.T) {
	t.Parallel()
	r := rdata.MustNewRP(wirebb.MustParse("admin.example.com"), wirebb.MustParse("info.example.com"))
	require.Equal(t, rrtype.RP, r.Type())

	got := packUnpack(t, r).(rdata.RP)
	require.True(t, r.Mbox().Equal(got.Mbox()))
	require.True(t, r.TxtDName().Equal(got.TxtDName()))
}

func TestAFSDB(t *testing.T) {
	t.Parallel()
	r := rdata.MustNewAFSDB(1, wirebb.MustParse("afs.example.com"))
	require.Equal(t, rrtype.AFSDB, r.Type())

	got := packUnpack(t, r).(rdata.AFSDB)
	require.Equal(t, uint16(1), got.Subtype())
	require.True(t, r.Hostname().Equal(got.Hostname()))
}

func TestX25(t *testing.T) {
	t.Parallel()
	r, err := rdata.NewX25("311061700956")
	require.NoError(t, err)

	got := packUnpack(t, r).(rdata.X25)
	require.Equal(t, "311061700956", got.PSDNAddress())
}

func TestISDN(t *testing.T) {
	t.Parallel()

	r, err := rdata.NewISDN("150862028003217", "", false)
	require.NoError(t, err)
	got := packUnpack(t, r).(rdata.ISDN)
	require.Equal(t, "150862028003217", got.Address())
	require.Equal(t, "", got.Subaddress())

	r2, err := rdata.NewISDN("150862028003217", "004", true)
	require.NoError(t, err)
	got2 := packUnpack(t, r2).(rdata.ISDN)
	require.Equal(t, "004", got2.Subaddress())
}

func TestRT(t *testing.T) {
	t.Parallel()
	r := rdata.MustNewRT(10, wirebb.MustParse("relay.example.com"))
	got := packUnpack(t, r).(rdata.RT)
	require.Equal(t, uint16(10), got.Preference())
	require.True(t, r.IntermediateHost().Equal(got.IntermediateHost()))
}

func TestNSAP(t *testing.T) {
	t.Parallel()
	addr := []byte{0x47, 0x00, 0x05, 0x80, 0x00, 0x5a, 0x00, 0x00, 0x00, 0x00,
		0x01, 0xe1, 0x33, 0xff, 0xfe, 0x64, 0xa8, 0x73, 0x00}
	r := rdata.NewNSAP(addr)
	require.Equal(t, rrtype.NSAP, r.Type())

	got := packUnpack(t, r).(rdata.NSAP)
	require.Equal(t, addr, got.Address())
}

func TestNSAPPTR(t *testing.T) {
	t.Parallel()
	r := rdata.MustNewNSAPPTR(wirebb.MustParse("foo.nsap.arpa"))
	got := packUnpack(t, r).(rdata.NSAPPTR)
	require.True(t, r.Owner().Equal(got.Owner()))
}

func TestLOC(t *testing.T) {
	t.Parallel()
	// arbitrary fixture
	r := rdata.NewLOC(0, 0x12, 0x16, 0x13, 0x8b0d2178, 0x7f560d2c, 0x00989cdc)
	require.Equal(t, rrtype.LOC, r.Type())

	got := packUnpack(t, r).(rdata.LOC)
	require.Equal(t, uint8(0), got.Version())
	require.Equal(t, uint8(0x12), got.Size())
	require.Equal(t, uint32(0x8b0d2178), got.Latitude())
	require.Equal(t, uint32(0x7f560d2c), got.Longitude())
	require.Equal(t, uint32(0x00989cdc), got.Altitude())
}
