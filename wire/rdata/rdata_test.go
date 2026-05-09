package rdata_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
	"github.com/stretchr/testify/require"
)

func packUnpack(t *testing.T, r rdata.RData) rdata.RData {
	t.Helper()
	p := wirebb.NewPacker(nil)
	r.Pack(p)
	buf := p.Bytes()
	u := wirebb.NewUnpacker(buf)
	out, err := rdata.Unpack(r.Type(), u, len(buf))
	require.NoError(t, err)
	require.Equal(t, len(buf), u.Off())
	return out
}

func TestA(t *testing.T) {
	t.Parallel()
	r := rdata.MustNewA(netip.MustParseAddr("93.184.216.34"))
	require.Equal(t, rrtype.A, r.Type())
	require.Equal(t, netip.MustParseAddr("93.184.216.34"), r.Addr())

	got := packUnpack(t, r).(rdata.A)
	require.Equal(t, r.Addr(), got.Addr())
}

func TestANewRejectsV6(t *testing.T) {
	t.Parallel()
	require.Panics(t, func() {
		rdata.MustNewA(netip.MustParseAddr("::1"))
	})
}

func TestAAAA(t *testing.T) {
	t.Parallel()
	r := rdata.MustNewAAAA(netip.MustParseAddr("2606:2800:220:1:248:1893:25c8:1946"))
	require.Equal(t, rrtype.AAAA, r.Type())

	got := packUnpack(t, r).(rdata.AAAA)
	require.Equal(t, r.Addr(), got.Addr())
}

func TestCNAME(t *testing.T) {
	t.Parallel()
	r := rdata.MustNewCNAME(wirebb.MustParse("alias.example.com"))
	require.Equal(t, rrtype.CNAME, r.Type())
	require.Equal(t, "alias.example.com.", r.Target().String())

	got := packUnpack(t, r).(rdata.CNAME)
	require.True(t, r.Target().Equal(got.Target()))
}

func TestNS(t *testing.T) {
	t.Parallel()
	r := rdata.MustNewNS(wirebb.MustParse("ns1.example.com"))
	got := packUnpack(t, r).(rdata.NS)
	require.True(t, r.NSDName().Equal(got.NSDName()))
}

func TestPTR(t *testing.T) {
	t.Parallel()
	r := rdata.MustNewPTR(wirebb.MustParse("host.example.com"))
	got := packUnpack(t, r).(rdata.PTR)
	require.True(t, r.PtrDName().Equal(got.PtrDName()))
}

func TestMX(t *testing.T) {
	t.Parallel()
	r := rdata.MustNewMX(10, wirebb.MustParse("mail.example.com"))
	require.Equal(t, uint16(10), r.Preference())
	require.Equal(t, "mail.example.com.", r.Exchange().String())

	got := packUnpack(t, r).(rdata.MX)
	require.Equal(t, r.Preference(), got.Preference())
	require.True(t, r.Exchange().Equal(got.Exchange()))
}

func TestTXT(t *testing.T) {
	t.Parallel()
	r, err := rdata.NewTXT("v=spf1", "-all")
	require.NoError(t, err)
	require.Equal(t, []string{"v=spf1", "-all"}, r.Strings())

	got := packUnpack(t, r).(rdata.TXT)
	require.Equal(t, r.Strings(), got.Strings())

	_, err = rdata.NewTXT(string(make([]byte, 256)))
	require.Error(t, err)
}

func TestSOA(t *testing.T) {
	t.Parallel()
	r := rdata.MustNewSOA(
		wirebb.MustParse("ns.example.com"),
		wirebb.MustParse("hostmaster.example.com"),
		2024010100,
		3600*time.Second,
		600*time.Second,
		86400*time.Second,
		3600*time.Second,
	)
	require.Equal(t, uint32(2024010100), r.Serial())
	require.Equal(t, 3600*time.Second, r.Refresh())

	got := packUnpack(t, r).(rdata.SOA)
	require.True(t, r.MName().Equal(got.MName()))
	require.True(t, r.RName().Equal(got.RName()))
	require.Equal(t, r.Serial(), got.Serial())
	require.Equal(t, r.Refresh(), got.Refresh())
	require.Equal(t, r.Retry(), got.Retry())
	require.Equal(t, r.Expire(), got.Expire())
	require.Equal(t, r.Minimum(), got.Minimum())
}

func TestUnknown(t *testing.T) {
	t.Parallel()
	payload := []byte{0xde, 0xad, 0xbe, 0xef}
	r := rdata.NewUnknown(rrtype.Type(65000), payload)
	require.Equal(t, rrtype.Type(65000), r.Type())
	require.Equal(t, payload, r.Bytes())

	got := packUnpack(t, r).(rdata.Unknown)
	require.Equal(t, payload, got.Bytes())
}
