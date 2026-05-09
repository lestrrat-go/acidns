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

func TestDNSKEYAccessors(t *testing.T) {
	t.Parallel()
	k := rdata.NewDNSKEY(257, 3, rdata.AlgED25519, []byte{1, 2, 3, 4})
	require.Equal(t, uint16(257), k.Flags())
	require.Equal(t, uint8(3), k.Protocol())
	require.Equal(t, rdata.AlgED25519, k.Algorithm())
	require.Equal(t, []byte{1, 2, 3, 4}, k.PublicKey())
}

func TestDSAccessors(t *testing.T) {
	t.Parallel()
	d := rdata.NewDS(0xfeed, rdata.AlgRSASHA256, rdata.DigestSHA256, []byte{0xaa})
	require.Equal(t, uint16(0xfeed), d.KeyTag())
	require.Equal(t, rdata.AlgRSASHA256, d.Algorithm())
	require.Equal(t, rdata.DigestSHA256, d.DigestType())
	require.Equal(t, []byte{0xaa}, d.Digest())
}

func TestRRSIGAccessors(t *testing.T) {
	t.Parallel()
	exp := time.Now().UTC().Truncate(time.Second).Add(time.Hour)
	inc := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	r := rdata.NewRRSIG(rrtype.A, rdata.AlgRSASHA256, 3, time.Hour,
		exp, inc, 1234, wirebb.MustParse("example.com"), []byte{0xab})
	require.Equal(t, rrtype.A, r.TypeCovered())
	require.Equal(t, rdata.AlgRSASHA256, r.Algorithm())
	require.Equal(t, uint8(3), r.Labels())
	require.Equal(t, time.Hour, r.OriginalTTL())
}

func TestNSEC3PARAMAccessors(t *testing.T) {
	t.Parallel()
	p := rdata.MustNewNSEC3PARAM(1, 0, 100, []byte{0xca, 0xfe})
	require.Equal(t, uint8(1), p.HashAlgorithm())
	require.Equal(t, uint8(0), p.Flags())
}

func TestNSEC3Accessors(t *testing.T) {
	t.Parallel()
	n := rdata.MustNewNSEC3(1, 2, 3, []byte{0x01}, []byte{0x02}, []rrtype.Type{rrtype.A})
	require.Equal(t, uint8(1), n.HashAlgorithm())
	require.Equal(t, uint8(2), n.Flags())
	require.Equal(t, uint16(3), n.Iterations())
}

func TestHIPAlgorithmAccessor(t *testing.T) {
	t.Parallel()
	h, err := rdata.NewHIP(rdata.HIPAlgRSA, []byte{0x01}, []byte{0x02})
	require.NoError(t, err)
	require.Equal(t, rdata.HIPAlgRSA, h.Algorithm())
}

func TestILNPPreferenceAccessors(t *testing.T) {
	t.Parallel()
	require.Equal(t, uint16(10), rdata.NewNID(10, 0).Preference())
	require.Equal(t, uint16(20), rdata.NewL32(20, 0).Preference())
	require.Equal(t, uint16(30), rdata.NewL64(30, 0).Preference())
	require.Equal(t, uint16(40), rdata.MustNewLP(40, wirebb.MustParse("a.b")).Preference())
}

func TestIPSECKEYAccessors(t *testing.T) {
	t.Parallel()
	k, err := rdata.NewIPSECKEYAddr(7, rdata.IPSECKEYAlgRSA, netip.MustParseAddr("192.0.2.1"), nil)
	require.NoError(t, err)
	require.Equal(t, uint8(7), k.Precedence())
	require.Equal(t, rdata.IPSECKEYAlgRSA, k.Algorithm())
}

func TestLOCAccessors(t *testing.T) {
	t.Parallel()
	l := rdata.NewLOC(0, 0x12, 0x16, 0x13, 1, 2, 3)
	require.Equal(t, uint8(0x16), l.HorizPre())
	require.Equal(t, uint8(0x13), l.VertPre())
}

func TestNAPTRAccessors(t *testing.T) {
	t.Parallel()
	n, err := rdata.NewNAPTR(1, 2, "U", "E2U+sip", "!^.*$!sip:!", wirebb.MustParse("example.com"))
	require.NoError(t, err)
	require.Equal(t, "!^.*$!sip:!", n.Regexp())
	require.True(t, n.Replacement().Equal(wirebb.MustParse("example.com")))
}

func TestZONEMDAccessors(t *testing.T) {
	t.Parallel()
	z := rdata.NewZONEMD(1, rdata.ZONEMDSchemeSimple, rdata.ZONEMDHashSHA384, []byte{0xff})
	require.Equal(t, rdata.ZONEMDHashSHA384, z.HashAlgorithm())
}

func TestSVCBPropertiesAccessors(t *testing.T) {
	t.Parallel()
	s := rdata.MustNewSVCB(1, wirebb.MustParse("example.com"))
	require.Equal(t, "example.com.", s.Target().String())
	require.Empty(t, s.Params())
	_, hasPort := s.Port()
	require.False(t, hasPort)
	require.Empty(t, s.IPv4Hints())
	require.Empty(t, s.IPv6Hints())
	require.Empty(t, s.ALPN())
	_, hasDoH := s.DOHPath()
	require.False(t, hasDoH)
}

func TestSVCBParamRoundTrip(t *testing.T) {
	t.Parallel()
	alpn, err := rdata.NewSvcParamALPN("h2", "h3")
	require.NoError(t, err)
	v4, err := rdata.NewSvcParamIPv4Hint(netip.MustParseAddr("192.0.2.1"))
	require.NoError(t, err)
	v6, err := rdata.NewSvcParamIPv6Hint(netip.MustParseAddr("2001:db8::1"))
	require.NoError(t, err)
	s := rdata.MustNewSVCB(1, wirebb.MustParse("example.com"),
		alpn,
		rdata.NewSvcParamPort(443),
		v4, v6,
		rdata.NewSvcParamDOHPath("/dns-query{?dns}"),
		rdata.NewSVCBParam(rdata.SvcParamECH, []byte{0xab, 0xcd}),
	)
	port, ok := s.Port()
	require.True(t, ok)
	require.Equal(t, uint16(443), port)
	require.Equal(t, []string{"h2", "h3"}, s.ALPN())
	require.Len(t, s.IPv4Hints(), 1)
	require.Len(t, s.IPv6Hints(), 1)
	path, ok := s.DOHPath()
	require.True(t, ok)
	require.Equal(t, "/dns-query{?dns}", path)
}

func TestSvcParamErrors(t *testing.T) {
	t.Parallel()
	_, err := rdata.NewSvcParamALPN("")
	require.Error(t, err)
	_, err = rdata.NewSvcParamIPv4Hint(netip.MustParseAddr("::1"))
	require.Error(t, err)
	_, err = rdata.NewSvcParamIPv6Hint(netip.MustParseAddr("192.0.2.1"))
	require.Error(t, err)
}

func TestNSECRoundTrip(t *testing.T) {
	t.Parallel()
	n := rdata.NewNSEC(wirebb.MustParse("next.example."), []rrtype.Type{rrtype.A, rrtype.RRSIG, rrtype.NSEC})
	require.Equal(t, "next.example.", n.NextDomainName().String())
}
