package rdata_test

import (
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/stretchr/testify/require"
)

func TestDNSKEY(t *testing.T) {
	t.Parallel()
	r := rdata.NewDNSKEY(257, 3, rdata.AlgECDSAP256SHA256, []byte{1, 2, 3, 4, 5, 6, 7, 8})
	require.Equal(t, uint16(257), r.Flags())
	require.Equal(t, rdata.AlgECDSAP256SHA256, r.Algorithm())

	got := packUnpack(t, r).(rdata.DNSKEY)
	require.Equal(t, r.Flags(), got.Flags())
	require.Equal(t, r.PublicKey(), got.PublicKey())
}

func TestDS(t *testing.T) {
	t.Parallel()
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i)
	}
	r := rdata.NewDS(12345, rdata.AlgECDSAP256SHA256, rdata.DigestSHA256, digest)
	got := packUnpack(t, r).(rdata.DS)
	require.Equal(t, r.KeyTag(), got.KeyTag())
	require.Equal(t, r.Digest(), got.Digest())
}

func TestRRSIG(t *testing.T) {
	t.Parallel()
	exp := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	inc := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	r := rdata.NewRRSIG(rrtype.A, rdata.AlgED25519, 2,
		3600*time.Second, exp, inc, 5678,
		dnsname.MustParse("example.com"), []byte{0xaa, 0xbb, 0xcc})

	got := packUnpack(t, r).(rdata.RRSIG)
	require.Equal(t, rrtype.A, got.TypeCovered())
	require.Equal(t, exp, got.SignatureExpiration())
	require.Equal(t, inc, got.SignatureInception())
	require.Equal(t, uint16(5678), got.KeyTag())
	require.True(t, got.SignerName().Equal(dnsname.MustParse("example.com")))
	require.Equal(t, []byte{0xaa, 0xbb, 0xcc}, got.Signature())
}

func TestNSEC(t *testing.T) {
	t.Parallel()
	types := []rrtype.Type{rrtype.A, rrtype.MX, rrtype.AAAA, rrtype.RRSIG, rrtype.NSEC}
	r := rdata.NewNSEC(dnsname.MustParse("next.example.com"), types)

	got := packUnpack(t, r).(rdata.NSEC)
	require.True(t, got.NextDomainName().Equal(dnsname.MustParse("next.example.com")))
	require.ElementsMatch(t, types, got.Types())
}

func TestNSEC3(t *testing.T) {
	t.Parallel()
	salt := []byte{0xde, 0xad, 0xbe, 0xef}
	hash := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	types := []rrtype.Type{rrtype.A, rrtype.RRSIG}
	r := rdata.NewNSEC3(1, 0, 100, salt, hash, types)

	got := packUnpack(t, r).(rdata.NSEC3)
	require.Equal(t, salt, got.Salt())
	require.Equal(t, hash, got.NextHashedOwner())
	require.ElementsMatch(t, types, got.Types())
}
