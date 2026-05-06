package rdata_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/stretchr/testify/require"
)

func TestTLSAAccessors(t *testing.T) {
	t.Parallel()
	r := rdata.NewTLSA(rdata.TLSAUsageDANEEE, rdata.TLSASelectorSPKI, rdata.TLSAMatchingSHA256, []byte{1, 2, 3})
	require.Equal(t, rdata.TLSAUsageDANEEE, r.Usage())
	require.Equal(t, rdata.TLSASelectorSPKI, r.Selector())
	require.Equal(t, rdata.TLSAMatchingSHA256, r.MatchingType())
}

func TestSMIMEAAccessors(t *testing.T) {
	t.Parallel()
	r := rdata.NewSMIMEA(rdata.TLSAUsageDANEEE, rdata.TLSASelectorFullCert, rdata.TLSAMatchingFull, []byte{0xff})
	require.Equal(t, rdata.TLSAUsageDANEEE, r.Usage())
	require.Equal(t, rdata.TLSASelectorFullCert, r.Selector())
	require.Equal(t, rdata.TLSAMatchingFull, r.MatchingType())
}

func TestSSHFPFingerprintType(t *testing.T) {
	t.Parallel()
	r := rdata.NewSSHFP(rdata.SSHFPAlgRSA, rdata.SSHFPTypeSHA256, []byte{0x42})
	require.Equal(t, rdata.SSHFPTypeSHA256, r.FingerprintType())
}

func TestRDataPack(t *testing.T) {
	t.Parallel()
	rd := rdata.NewA(netip.MustParseAddr("192.0.2.1"))
	got := rdata.Pack(rd)
	require.Equal(t, []byte{192, 0, 2, 1}, got)
}

func TestUnknownRDataPath(t *testing.T) {
	t.Parallel()
	rd := rdata.NewUnknown(rrtype.Type(65000), []byte{0xa, 0xb, 0xc})
	require.Equal(t, []byte{0xa, 0xb, 0xc}, rd.Bytes())
	got := rdata.Pack(rd)
	require.Equal(t, []byte{0xa, 0xb, 0xc}, got)
}

func TestSOAAccessorsAll(t *testing.T) {
	t.Parallel()
	soa := rdata.NewSOA(
		dnsname.MustParse("ns.example.com"),
		dnsname.MustParse("hm.example.com"),
		1, 2*time.Hour, 30*time.Minute, 7*24*time.Hour, 60*time.Second,
	)
	require.Equal(t, "ns.example.com.", soa.MName().String())
	require.Equal(t, "hm.example.com.", soa.RName().String())
	require.Equal(t, uint32(1), soa.Serial())
	require.Equal(t, 2*time.Hour, soa.Refresh())
	require.Equal(t, 30*time.Minute, soa.Retry())
	require.Equal(t, 7*24*time.Hour, soa.Expire())
	require.Equal(t, 60*time.Second, soa.Minimum())
}

func TestCAAAccessors(t *testing.T) {
	t.Parallel()
	r, err := rdata.NewCAA(0x80, "issue", []byte("letsencrypt.org"))
	require.NoError(t, err)
	require.Equal(t, uint8(0x80), r.Flags())
	require.Equal(t, "issue", r.Tag())
	require.Equal(t, []byte("letsencrypt.org"), r.Value())
}
