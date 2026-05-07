package rdata_test

import (
	"testing"

	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
	"github.com/stretchr/testify/require"
)

func TestSRV(t *testing.T) {
	t.Parallel()
	r := rdata.NewSRV(10, 100, 443, wirebb.MustParse("svc.example.com"))
	require.Equal(t, rrtype.SRV, r.Type())
	require.Equal(t, uint16(443), r.Port())

	got := packUnpack(t, r).(rdata.SRV)
	require.Equal(t, r.Priority(), got.Priority())
	require.Equal(t, r.Weight(), got.Weight())
	require.Equal(t, r.Port(), got.Port())
	require.True(t, r.Target().Equal(got.Target()))
}

func TestTLSA(t *testing.T) {
	t.Parallel()
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i)
	}
	r := rdata.NewTLSA(rdata.TLSAUsageDANEEE, rdata.TLSASelectorSPKI, rdata.TLSAMatchingSHA256, digest)
	require.Equal(t, rrtype.TLSA, r.Type())

	got := packUnpack(t, r).(rdata.TLSA)
	require.Equal(t, r.Usage(), got.Usage())
	require.Equal(t, digest, got.CertificateAssociation())
}

func TestSMIMEA(t *testing.T) {
	t.Parallel()
	digest := []byte{0xde, 0xad, 0xbe, 0xef}
	r := rdata.NewSMIMEA(rdata.TLSAUsageDANEEE, rdata.TLSASelectorFullCert, rdata.TLSAMatchingFull, digest)
	require.Equal(t, rrtype.SMIMEA, r.Type())

	got := packUnpack(t, r).(rdata.SMIMEA)
	require.Equal(t, digest, got.CertificateAssociation())
}

func TestCSYNC(t *testing.T) {
	t.Parallel()
	r := rdata.NewCSYNC(2024010100, 3, []rrtype.Type{rrtype.A, rrtype.NS, rrtype.AAAA})
	require.Equal(t, rrtype.CSYNC, r.Type())

	got := packUnpack(t, r).(rdata.CSYNC)
	require.Equal(t, uint32(2024010100), got.SOASerial())
	require.Equal(t, uint16(3), got.Flags())
	require.ElementsMatch(t, []rrtype.Type{rrtype.A, rrtype.NS, rrtype.AAAA}, got.Types())
}

func TestNAPTR(t *testing.T) {
	t.Parallel()
	r, err := rdata.NewNAPTR(100, 50, "U", "E2U+sip", `!^.*$!sip:info@example.com!`,
		wirebb.MustParse("."))
	require.NoError(t, err)
	require.Equal(t, rrtype.NAPTR, r.Type())

	got := packUnpack(t, r).(rdata.NAPTR)
	require.Equal(t, uint16(100), got.Order())
	require.Equal(t, uint16(50), got.Preference())
	require.Equal(t, "U", got.Flags())
	require.Equal(t, "E2U+sip", got.Services())
}

func TestSSHFP(t *testing.T) {
	t.Parallel()
	fp := make([]byte, 32)
	for i := range fp {
		fp[i] = byte(i ^ 0xaa)
	}
	r := rdata.NewSSHFP(rdata.SSHFPAlgED25519, rdata.SSHFPTypeSHA256, fp)
	require.Equal(t, rrtype.SSHFP, r.Type())

	got := packUnpack(t, r).(rdata.SSHFP)
	require.Equal(t, rdata.SSHFPAlgED25519, got.Algorithm())
	require.Equal(t, fp, got.Fingerprint())
}

func TestNSEC3PARAM(t *testing.T) {
	t.Parallel()
	salt := []byte{0xca, 0xfe, 0xba, 0xbe}
	r := rdata.NewNSEC3PARAM(1, 0, 100, salt)
	got := packUnpack(t, r).(rdata.NSEC3PARAM)
	require.Equal(t, salt, got.Salt())
	require.Equal(t, uint16(100), got.Iterations())
}
