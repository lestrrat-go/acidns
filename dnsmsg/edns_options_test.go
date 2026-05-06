package dnsmsg_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/stretchr/testify/require"
)

func TestNSID(t *testing.T) {
	t.Parallel()
	o := dnsmsg.NewNSID([]byte("ns1.example."))
	require.Equal(t, dnsmsg.EDNSOptionNSID, o.Code())
	got, ok := dnsmsg.NSIDIdentifier(o)
	require.True(t, ok)
	require.Equal(t, []byte("ns1.example."), got)
}

func TestEDNSExpire(t *testing.T) {
	t.Parallel()
	o := dnsmsg.NewEDNSExpire(3600)
	secs, ok := dnsmsg.EDNSExpireSeconds(o)
	require.True(t, ok)
	require.Equal(t, uint32(3600), secs)

	q := dnsmsg.NewEDNSExpireQuery()
	_, ok = dnsmsg.EDNSExpireSeconds(q)
	require.False(t, ok)
}

func TestTCPKeepalive(t *testing.T) {
	t.Parallel()
	o := dnsmsg.NewTCPKeepalive(2 * time.Second)
	d, ok := dnsmsg.TCPKeepaliveTimeout(o)
	require.True(t, ok)
	require.Equal(t, 2*time.Second, d)

	empty := dnsmsg.NewTCPKeepalive(0)
	require.Empty(t, empty.Data())
}

func TestClientSubnet(t *testing.T) {
	t.Parallel()
	o, err := dnsmsg.NewClientSubnet(netip.MustParsePrefix("192.0.2.0/24"), 0)
	require.NoError(t, err)
	prefix, scope, ok := dnsmsg.ClientSubnet(o)
	require.True(t, ok)
	require.Equal(t, "192.0.2.0/24", prefix.String())
	require.Equal(t, uint8(0), scope)

	o6, err := dnsmsg.NewClientSubnet(netip.MustParsePrefix("2001:db8::/56"), 56)
	require.NoError(t, err)
	prefix6, scope6, ok := dnsmsg.ClientSubnet(o6)
	require.True(t, ok)
	require.Equal(t, "2001:db8::/56", prefix6.String())
	require.Equal(t, uint8(56), scope6)
}

func TestDNSCookies(t *testing.T) {
	t.Parallel()
	cc := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	o := dnsmsg.NewClientCookie(cc)
	got, srv, ok := dnsmsg.Cookies(o)
	require.True(t, ok)
	require.Equal(t, cc, got)
	require.Empty(t, srv)

	srvCookie := []byte{0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8}
	o2, err := dnsmsg.NewClientServerCookie(cc, srvCookie)
	require.NoError(t, err)
	gotC, gotS, ok := dnsmsg.Cookies(o2)
	require.True(t, ok)
	require.Equal(t, cc, gotC)
	require.Equal(t, srvCookie, gotS)

	_, err = dnsmsg.NewClientServerCookie(cc, []byte{0x01})
	require.Error(t, err)
}

func TestExtendedError(t *testing.T) {
	t.Parallel()
	o := dnsmsg.NewExtendedError(dnsmsg.ExtendedErrorDNSSECBogus, "RRSIG expired")
	code, text, ok := dnsmsg.ExtendedError(o)
	require.True(t, ok)
	require.Equal(t, dnsmsg.ExtendedErrorDNSSECBogus, code)
	require.Equal(t, "RRSIG expired", text)
}

func TestZoneVersion(t *testing.T) {
	t.Parallel()
	q := dnsmsg.NewZoneVersionQuery()
	require.Empty(t, q.Data())

	o := dnsmsg.NewZoneVersionSOASerial(2, 2024010100)
	lc, serial, ok := dnsmsg.ZoneVersionSOASerial(o)
	require.True(t, ok)
	require.Equal(t, uint8(2), lc)
	require.Equal(t, uint32(2024010100), serial)
}
