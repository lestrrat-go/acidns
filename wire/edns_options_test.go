package wire_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/stretchr/testify/require"
)

func TestNSID(t *testing.T) {
	t.Parallel()
	o := wire.NewNSID([]byte("ns1.example."))
	require.Equal(t, wire.EDNSOptionNSID, o.Code())
	got, ok := wire.NSIDIdentifier(o)
	require.True(t, ok)
	require.Equal(t, []byte("ns1.example."), got)
}

func TestEDNSExpire(t *testing.T) {
	t.Parallel()
	o := wire.NewEDNSExpire(3600)
	secs, ok := wire.EDNSExpireSeconds(o)
	require.True(t, ok)
	require.Equal(t, uint32(3600), secs)

	q := wire.NewEDNSExpireQuery()
	_, ok = wire.EDNSExpireSeconds(q)
	require.False(t, ok)
}

func TestTCPKeepalive(t *testing.T) {
	t.Parallel()
	o := wire.NewTCPKeepalive(2 * time.Second)
	d, ok := wire.TCPKeepaliveTimeout(o)
	require.True(t, ok)
	require.Equal(t, 2*time.Second, d)

	empty := wire.NewTCPKeepalive(0)
	require.Empty(t, empty.Data())
}

func TestClientSubnet(t *testing.T) {
	t.Parallel()
	o, err := wire.NewClientSubnet(netip.MustParsePrefix("192.0.2.0/24"), 0)
	require.NoError(t, err)
	prefix, scope, ok := wire.ClientSubnet(o)
	require.True(t, ok)
	require.Equal(t, "192.0.2.0/24", prefix.String())
	require.Equal(t, uint8(0), scope)

	o6, err := wire.NewClientSubnet(netip.MustParsePrefix("2001:db8::/56"), 56)
	require.NoError(t, err)
	prefix6, scope6, ok := wire.ClientSubnet(o6)
	require.True(t, ok)
	require.Equal(t, "2001:db8::/56", prefix6.String())
	require.Equal(t, uint8(56), scope6)
}

// RFC 7871 §6: bits beyond the source-prefix MUST be zero on the wire.
// A non-byte-aligned source-prefix carries up to 7 caller-supplied IP
// bits in the last address byte; the encoder must mask them off so the
// declared privacy boundary is the on-wire boundary.
func TestClientSubnet_TrailingBitsMaskedOnEncode(t *testing.T) {
	t.Parallel()
	// 192.0.2.137/20: last meaningful byte is data[6] (4 header + 3),
	// source/8 = 2 bytes whole + 4 bits in the third byte. The third
	// byte should retain only the high 4 bits of 0x02 → 0x00.
	o, err := wire.NewClientSubnet(netip.MustParsePrefix("192.0.2.137/20"), 0)
	require.NoError(t, err)
	d := o.Data()
	require.Len(t, d, 4+3)
	require.Equal(t, byte(0xc0), d[4])   // 192 — full byte
	require.Equal(t, byte(0x00), d[5])   // 0 — full byte
	require.Equal(t, byte(0x00), d[6])   // 2 → masked to 0 (top 4 bits of 0x02 are zero)

	// Decoder accepts what encoder emits (round-trip).
	prefix, _, ok := wire.ClientSubnet(o)
	require.True(t, ok)
	require.Equal(t, "192.0.0.0/20", prefix.String())
}

func TestDNSCookies(t *testing.T) {
	t.Parallel()
	cc := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	o := wire.NewClientCookie(cc)
	got, srv, ok := wire.Cookies(o)
	require.True(t, ok)
	require.Equal(t, cc, got)
	require.Empty(t, srv)

	srvCookie := []byte{0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8}
	o2, err := wire.NewClientServerCookie(cc, srvCookie)
	require.NoError(t, err)
	gotC, gotS, ok := wire.Cookies(o2)
	require.True(t, ok)
	require.Equal(t, cc, gotC)
	require.Equal(t, srvCookie, gotS)

	_, err = wire.NewClientServerCookie(cc, []byte{0x01})
	require.Error(t, err)
}

func TestExtendedError(t *testing.T) {
	t.Parallel()
	o := wire.NewExtendedError(wire.ExtendedErrorDNSSECBogus, "RRSIG expired")
	code, text, ok := wire.ExtendedError(o)
	require.True(t, ok)
	require.Equal(t, wire.ExtendedErrorDNSSECBogus, code)
	require.Equal(t, "RRSIG expired", text)
}

func TestZoneVersion(t *testing.T) {
	t.Parallel()
	q := wire.NewZoneVersionQuery()
	require.Empty(t, q.Data())

	o := wire.NewZoneVersionSOASerial(2, 2024010100)
	lc, serial, ok := wire.ZoneVersionSOASerial(o)
	require.True(t, ok)
	require.Equal(t, uint8(2), lc)
	require.Equal(t, uint32(2024010100), serial)
}
