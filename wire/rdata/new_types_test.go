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

func TestDNAME(t *testing.T) {
	t.Parallel()
	r := rdata.NewDNAME(wirebb.MustParse("frob.example.com"))
	require.Equal(t, rrtype.DNAME, r.Type())
	require.Equal(t, "frob.example.com.", r.Target().String())

	got := packUnpack(t, r).(rdata.DNAME)
	require.True(t, r.Target().Equal(got.Target()))
}

func TestHINFO(t *testing.T) {
	t.Parallel()
	r, err := rdata.NewHINFO("PDP-11/70", "ULTRIX")
	require.NoError(t, err)
	require.Equal(t, rrtype.HINFO, r.Type())
	require.Equal(t, "PDP-11/70", r.CPU())
	require.Equal(t, "ULTRIX", r.OS())

	got := packUnpack(t, r).(rdata.HINFO)
	require.Equal(t, r.CPU(), got.CPU())
	require.Equal(t, r.OS(), got.OS())
}

func TestHINFORejectsTooLong(t *testing.T) {
	t.Parallel()
	long := make([]byte, 256)
	_, err := rdata.NewHINFO(string(long), "ok")
	require.Error(t, err)
	_, err = rdata.NewHINFO("ok", string(long))
	require.Error(t, err)
}

func TestKX(t *testing.T) {
	t.Parallel()
	r := rdata.NewKX(10, wirebb.MustParse("kx.example.com"))
	require.Equal(t, rrtype.KX, r.Type())
	require.Equal(t, uint16(10), r.Preference())

	got := packUnpack(t, r).(rdata.KX)
	require.Equal(t, r.Preference(), got.Preference())
	require.True(t, r.Exchanger().Equal(got.Exchanger()))
}

func TestCDS(t *testing.T) {
	t.Parallel()
	digest := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	r := rdata.NewCDS(12345, rdata.AlgRSASHA256, rdata.DigestSHA256, digest)
	require.Equal(t, rrtype.CDS, r.Type())
	require.Equal(t, uint16(12345), r.KeyTag())

	got := packUnpack(t, r).(rdata.CDS)
	require.Equal(t, r.KeyTag(), got.KeyTag())
	require.Equal(t, r.Algorithm(), got.Algorithm())
	require.Equal(t, r.DigestType(), got.DigestType())
	require.Equal(t, digest, got.Digest())
}

func TestCDSDeleteSentinel(t *testing.T) {
	t.Parallel()
	// RFC 8078 §4: (alg=0, dt=0, digest=0x00) means "delete the parent DS RRset".
	r := rdata.NewCDS(0, 0, 0, []byte{0})
	got := packUnpack(t, r).(rdata.CDS)
	require.Equal(t, []byte{0}, got.Digest())
	require.Equal(t, rdata.DNSSECAlgorithm(0), got.Algorithm())
}

func TestCDNSKEY(t *testing.T) {
	t.Parallel()
	pk := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	r := rdata.NewCDNSKEY(rdata.DNSKEYFlagZone|rdata.DNSKEYFlagSEP, 3, rdata.AlgED25519, pk)
	require.Equal(t, rrtype.CDNSKEY, r.Type())

	got := packUnpack(t, r).(rdata.CDNSKEY)
	require.Equal(t, r.Flags(), got.Flags())
	require.Equal(t, r.Protocol(), got.Protocol())
	require.Equal(t, r.Algorithm(), got.Algorithm())
	require.Equal(t, pk, got.PublicKey())
}

func TestOPENPGPKEY(t *testing.T) {
	t.Parallel()
	pk := []byte{0xc6, 0x5d, 0x04, 0x42, 0x00, 0x01, 0x02}
	r := rdata.NewOPENPGPKEY(pk)
	require.Equal(t, rrtype.OPENPGPKEY, r.Type())
	require.Equal(t, pk, r.PublicKey())

	got := packUnpack(t, r).(rdata.OPENPGPKEY)
	require.Equal(t, pk, got.PublicKey())
}

func TestCERT(t *testing.T) {
	t.Parallel()
	body := []byte{0x30, 0x82, 0x01, 0x00, 0xde, 0xad, 0xbe, 0xef}
	r := rdata.NewCERT(rdata.CERTTypePKIX, 4321, rdata.AlgRSASHA256, body)
	require.Equal(t, rrtype.CERT, r.Type())
	require.Equal(t, rdata.CERTTypePKIX, r.CertType())
	require.Equal(t, uint16(4321), r.KeyTag())

	got := packUnpack(t, r).(rdata.CERT)
	require.Equal(t, r.CertType(), got.CertType())
	require.Equal(t, r.KeyTag(), got.KeyTag())
	require.Equal(t, r.Algorithm(), got.Algorithm())
	require.Equal(t, body, got.Certificate())
}

func TestAMTRELAYNone(t *testing.T) {
	t.Parallel()
	r := rdata.NewAMTRELAYNone(7, true)
	require.Equal(t, rrtype.AMTRELAY, r.Type())
	require.True(t, r.Discovery())
	require.Equal(t, rdata.AMTRELAYTypeNone, r.RelayType())

	got := packUnpack(t, r).(rdata.AMTRELAY)
	require.Equal(t, r.Precedence(), got.Precedence())
	require.True(t, got.Discovery())
	require.Equal(t, rdata.AMTRELAYTypeNone, got.RelayType())
}

func TestAMTRELAYIPv4(t *testing.T) {
	t.Parallel()
	r, err := rdata.NewAMTRELAYAddr(1, false, netip.MustParseAddr("203.0.113.5"))
	require.NoError(t, err)
	require.Equal(t, rdata.AMTRELAYTypeIPv4, r.RelayType())

	got := packUnpack(t, r).(rdata.AMTRELAY)
	require.Equal(t, rdata.AMTRELAYTypeIPv4, got.RelayType())
	require.Equal(t, r.RelayAddr(), got.RelayAddr())
	require.False(t, got.Discovery())
}

func TestAMTRELAYIPv6(t *testing.T) {
	t.Parallel()
	r, err := rdata.NewAMTRELAYAddr(1, true, netip.MustParseAddr("2001:db8::1"))
	require.NoError(t, err)
	require.Equal(t, rdata.AMTRELAYTypeIPv6, r.RelayType())

	got := packUnpack(t, r).(rdata.AMTRELAY)
	require.Equal(t, rdata.AMTRELAYTypeIPv6, got.RelayType())
	require.Equal(t, r.RelayAddr(), got.RelayAddr())
	require.True(t, got.Discovery())
}

func TestAMTRELAYName(t *testing.T) {
	t.Parallel()
	r := rdata.MustNewAMTRELAYName(2, false, wirebb.MustParse("relay.example.com"))
	require.Equal(t, rdata.AMTRELAYTypeName, r.RelayType())

	got := packUnpack(t, r).(rdata.AMTRELAY)
	require.Equal(t, rdata.AMTRELAYTypeName, got.RelayType())
	require.True(t, r.RelayName().Equal(got.RelayName()))
}

func TestTKEY(t *testing.T) {
	t.Parallel()
	inc := time.Unix(1700000000, 0).UTC()
	exp := time.Unix(1700003600, 0).UTC()
	r, err := rdata.NewTKEY(
		wirebb.MustParse("gss-tsig"),
		inc, exp,
		rdata.TKEYModeGSSAPI,
		0,
		[]byte{0x01, 0x02, 0x03, 0x04},
		nil,
	)
	require.NoError(t, err)
	require.Equal(t, rrtype.TKEY, r.Type())

	got := packUnpack(t, r).(rdata.TKEY)
	require.True(t, r.Algorithm().Equal(got.Algorithm()))
	require.Equal(t, inc, got.Inception())
	require.Equal(t, exp, got.Expiration())
	require.Equal(t, rdata.TKEYModeGSSAPI, got.Mode())
	require.Equal(t, []byte{0x01, 0x02, 0x03, 0x04}, got.KeyData())
	require.Empty(t, got.OtherData())
}
