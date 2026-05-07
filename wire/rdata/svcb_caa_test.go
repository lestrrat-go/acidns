package rdata_test

import (
	"net/netip"
	"testing"

	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
	"github.com/stretchr/testify/require"
)

func TestSVCBRoundTrip(t *testing.T) {
	t.Parallel()

	r := rdata.NewSVCB(1, wirebb.MustParse("svc.example.com"),
		rdata.NewSVCBParam(rdata.SvcParamALPN, []byte{2, 'h', '2', 2, 'h', '3'}),
		rdata.NewSVCBParam(rdata.SvcParamPort, []byte{0x01, 0xbb}),
		rdata.NewSVCBParam(rdata.SvcParamIPv4Hint, []byte{192, 0, 2, 1, 192, 0, 2, 2}),
	)

	require.Equal(t, rrtype.SVCB, r.Type())
	require.Equal(t, []string{"h2", "h3"}, r.ALPN())
	port, ok := r.Port()
	require.True(t, ok)
	require.Equal(t, uint16(443), port)
	require.Equal(t, []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("192.0.2.2"),
	}, r.IPv4Hints())

	got := packUnpack(t, r).(rdata.SVCB)
	require.Equal(t, r.Priority(), got.Priority())
	require.True(t, r.Target().Equal(got.Target()))
	require.Equal(t, r.ALPN(), got.ALPN())
}

func TestHTTPSType(t *testing.T) {
	t.Parallel()
	r := rdata.NewHTTPS(1, wirebb.MustParse("example.com"))
	require.Equal(t, rrtype.HTTPS, r.Type())

	got := packUnpack(t, r).(rdata.HTTPS)
	require.Equal(t, rrtype.HTTPS, got.Type())
}

func TestCAA(t *testing.T) {
	t.Parallel()
	r, err := rdata.NewCAA(0, "issue", []byte("letsencrypt.org"))
	require.NoError(t, err)
	require.Equal(t, rrtype.CAA, r.Type())
	require.Equal(t, "issue", r.Tag())
	require.Equal(t, []byte("letsencrypt.org"), r.Value())

	got := packUnpack(t, r).(rdata.CAA)
	require.Equal(t, r.Flags(), got.Flags())
	require.Equal(t, r.Tag(), got.Tag())
	require.Equal(t, r.Value(), got.Value())

	_, err = rdata.NewCAA(0, "", nil)
	require.Error(t, err)
	_, err = rdata.NewCAA(0, "bad-tag!", nil)
	require.Error(t, err)
}

// Sanity-check the wire bytes match the spec layout for a small SVCB.
func TestSVCBWire(t *testing.T) {
	t.Parallel()
	r := rdata.NewSVCB(1, wirebb.MustParse("foo.example.com"),
		rdata.NewSVCBParam(rdata.SvcParamPort, []byte{0x01, 0xbb}),
	)
	p := wirebb.NewPacker(nil)
	r.Pack(p)
	got := p.Bytes()
	// priority(2) + target wire(17 = 3+foo+7+example+3+com+0) + key(2) + len(2) + value(2)
	require.Equal(t, 2+17+2+2+2, len(got))
}
