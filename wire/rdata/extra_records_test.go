package rdata_test

import (
	"net/netip"
	"testing"

	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
	"github.com/stretchr/testify/require"
)

func TestAPL(t *testing.T) {
	t.Parallel()
	v4, err := rdata.NewAPLItem(netip.MustParsePrefix("192.0.2.0/24"), false)
	require.NoError(t, err)
	v6, err := rdata.NewAPLItem(netip.MustParsePrefix("2001:db8::/32"), true)
	require.NoError(t, err)
	r := rdata.NewAPL(v4, v6)
	require.Equal(t, rrtype.APL, r.Type())

	got := packUnpack(t, r).(rdata.APL)
	require.Len(t, got.Items(), 2)
	require.Equal(t, rdata.APLFamilyIPv4, got.Items()[0].Family())
	require.Equal(t, "192.0.2.0/24", got.Items()[0].Prefix().String())
	require.False(t, got.Items()[0].Negate())
	require.Equal(t, rdata.APLFamilyIPv6, got.Items()[1].Family())
	require.True(t, got.Items()[1].Negate())
}

func TestIPSECKEYAddr(t *testing.T) {
	t.Parallel()
	pk := []byte{0x01, 0x02, 0x03}
	r, err := rdata.NewIPSECKEYAddr(10, rdata.IPSECKEYAlgRSA, netip.MustParseAddr("192.0.2.1"), pk)
	require.NoError(t, err)
	got := packUnpack(t, r).(rdata.IPSECKEY)
	require.Equal(t, rdata.IPSECKEYGatewayIPv4, got.GatewayType())
	require.Equal(t, "192.0.2.1", got.GatewayAddr().String())
	require.Equal(t, pk, got.PublicKey())
}

func TestIPSECKEYName(t *testing.T) {
	t.Parallel()
	pk := []byte{0xaa, 0xbb}
	r := rdata.MustNewIPSECKEYName(5, rdata.IPSECKEYAlgECDSA, wirebb.MustParse("gw.example.com"), pk)
	got := packUnpack(t, r).(rdata.IPSECKEY)
	require.Equal(t, rdata.IPSECKEYGatewayName, got.GatewayType())
	require.True(t, got.GatewayName().Equal(wirebb.MustParse("gw.example.com")))
	require.Equal(t, pk, got.PublicKey())
}

func TestIPSECKEYNoGateway(t *testing.T) {
	t.Parallel()
	r := rdata.NewIPSECKEYNoGateway(0, rdata.IPSECKEYAlgNone, nil)
	got := packUnpack(t, r).(rdata.IPSECKEY)
	require.Equal(t, rdata.IPSECKEYGatewayNone, got.GatewayType())
	require.Empty(t, got.PublicKey())
}

func TestDHCID(t *testing.T) {
	t.Parallel()
	d := []byte{0xde, 0xad, 0xbe, 0xef}
	r := rdata.NewDHCID(d)
	got := packUnpack(t, r).(rdata.DHCID)
	require.Equal(t, d, got.Bytes())
}

func TestHIP(t *testing.T) {
	t.Parallel()
	hit := []byte{0x20, 0x01, 0xde, 0xad}
	pk := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	r, err := rdata.NewHIP(rdata.HIPAlgRSA, hit, pk, wirebb.MustParse("rvs.example.com"))
	require.NoError(t, err)

	got := packUnpack(t, r).(rdata.HIP)
	require.Equal(t, hit, got.HIT())
	require.Equal(t, pk, got.PublicKey())
	require.Len(t, got.RendezvousServers(), 1)
}

func TestNID(t *testing.T) {
	t.Parallel()
	r := rdata.NewNID(10, 0x0014020100000000)
	got := packUnpack(t, r).(rdata.NID)
	require.Equal(t, uint16(10), got.Preference())
	require.Equal(t, uint64(0x0014020100000000), got.NodeID())
}

func TestL32(t *testing.T) {
	t.Parallel()
	r := rdata.NewL32(20, 0x0a000001)
	got := packUnpack(t, r).(rdata.L32)
	require.Equal(t, uint32(0x0a000001), got.Locator())
}

func TestL64(t *testing.T) {
	t.Parallel()
	r := rdata.NewL64(30, 0x2001_0db8_1140_1000)
	got := packUnpack(t, r).(rdata.L64)
	require.Equal(t, uint64(0x2001_0db8_1140_1000), got.Locator())
}

func TestLP(t *testing.T) {
	t.Parallel()
	r := rdata.MustNewLP(40, wirebb.MustParse("l64.example.com"))
	got := packUnpack(t, r).(rdata.LP)
	require.True(t, got.FQDN().Equal(wirebb.MustParse("l64.example.com")))
}

func TestEUI48(t *testing.T) {
	t.Parallel()
	r := rdata.NewEUI48([6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	got := packUnpack(t, r).(rdata.EUI48)
	require.Equal(t, [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, got.Address())
}

func TestEUI64(t *testing.T) {
	t.Parallel()
	r := rdata.NewEUI64([8]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77})
	got := packUnpack(t, r).(rdata.EUI64)
	require.Equal(t, [8]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}, got.Address())
}

func TestURI(t *testing.T) {
	t.Parallel()
	r, err := rdata.NewURI(10, 1, "https://example.com/")
	require.NoError(t, err)
	got := packUnpack(t, r).(rdata.URI)
	require.Equal(t, uint16(10), got.Priority())
	require.Equal(t, uint16(1), got.Weight())
	require.Equal(t, "https://example.com/", got.Target())

	_, err = rdata.NewURI(0, 0, "")
	require.Error(t, err)
}

func TestZONEMD(t *testing.T) {
	t.Parallel()
	digest := make([]byte, 48)
	for i := range digest {
		digest[i] = byte(i)
	}
	r := rdata.NewZONEMD(2024010100, rdata.ZONEMDSchemeSimple, rdata.ZONEMDHashSHA384, digest)
	got := packUnpack(t, r).(rdata.ZONEMD)
	require.Equal(t, uint32(2024010100), got.Serial())
	require.Equal(t, rdata.ZONEMDSchemeSimple, got.Scheme())
	require.Equal(t, digest, got.Digest())
}

func TestRESINFO(t *testing.T) {
	t.Parallel()
	r, err := rdata.NewRESINFO("qnamemin", "exterr=15")
	require.NoError(t, err)
	got := packUnpack(t, r).(rdata.RESINFO)
	require.Equal(t, []string{"qnamemin", "exterr=15"}, got.Strings())
}

func TestSPF(t *testing.T) {
	t.Parallel()
	r, err := rdata.NewSPF("v=spf1", "-all")
	require.NoError(t, err)
	got := packUnpack(t, r).(rdata.SPF)
	require.Equal(t, []string{"v=spf1", "-all"}, got.Strings())
}
