package rdata_test

import (
	"math"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
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
	rd, err := rdata.NewA(netip.MustParseAddr("192.0.2.1"))
	require.NoError(t, err)
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
	soa, err := rdata.NewSOA(
		wirebb.MustParse("ns.example.com"),
		wirebb.MustParse("hm.example.com"),
		1, 2*time.Hour, 30*time.Minute, 7*24*time.Hour, 60*time.Second,
	)
	require.NoError(t, err)
	require.Equal(t, "ns.example.com.", soa.MName().String())
	require.Equal(t, "hm.example.com.", soa.RName().String())
	require.Equal(t, uint32(1), soa.Serial())
	require.Equal(t, 2*time.Hour, soa.Refresh())
	require.Equal(t, 30*time.Minute, soa.Retry())
	require.Equal(t, 7*24*time.Hour, soa.Expire())
	require.Equal(t, 60*time.Second, soa.Minimum())
}

// NewSOA must reject each timer field independently when it is negative.
// A negative time.Duration silently wraps to a huge uint32 on the wire
// (~136-year value); rejection at the constructor prevents that footgun.
func TestNewSOA_RejectsNegativeTimers(t *testing.T) {
	t.Parallel()
	mname := wirebb.MustParse("ns.example.com")
	rname := wirebb.MustParse("hm.example.com")
	cases := []struct {
		name                            string
		refresh, retry, expire, minimum time.Duration
	}{
		{"refresh", -1 * time.Second, 30 * time.Minute, 7 * 24 * time.Hour, 60 * time.Second},
		{"retry", 2 * time.Hour, -1 * time.Second, 7 * 24 * time.Hour, 60 * time.Second},
		{"expire", 2 * time.Hour, 30 * time.Minute, -1 * time.Second, 60 * time.Second},
		{"minimum", 2 * time.Hour, 30 * time.Minute, 7 * 24 * time.Hour, -1 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := rdata.NewSOA(mname, rname, 1, tc.refresh, tc.retry, tc.expire, tc.minimum)
			require.Error(t, err)
			require.ErrorIs(t, err, rdata.ErrInvalidRData)
		})
	}
}

// NewSOA must reject timer values above RFC 2308 §8 ceiling (2^31-1
// seconds). Anything above silently wraps when downstream encoders
// divide into seconds for the 32-bit wire field.
func TestNewSOA_RejectsTimersAboveRFC2308Ceiling(t *testing.T) {
	t.Parallel()
	mname := wirebb.MustParse("ns.example.com")
	rname := wirebb.MustParse("hm.example.com")
	tooBig := time.Duration(math.MaxInt32+1) * time.Second
	cases := []struct {
		name                            string
		refresh, retry, expire, minimum time.Duration
	}{
		{"refresh", tooBig, 30 * time.Minute, 7 * 24 * time.Hour, 60 * time.Second},
		{"retry", 2 * time.Hour, tooBig, 7 * 24 * time.Hour, 60 * time.Second},
		{"expire", 2 * time.Hour, 30 * time.Minute, tooBig, 60 * time.Second},
		{"minimum", 2 * time.Hour, 30 * time.Minute, 7 * 24 * time.Hour, tooBig},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := rdata.NewSOA(mname, rname, 1, tc.refresh, tc.retry, tc.expire, tc.minimum)
			require.Error(t, err)
			require.ErrorIs(t, err, rdata.ErrInvalidRData)
		})
	}
}

// Zero timers remain valid (some legitimate test/dev zones use them);
// the RFC 2308 §8 ceiling is at the maximum, not the minimum.
func TestNewSOA_AcceptsZeroTimers(t *testing.T) {
	t.Parallel()
	soa, err := rdata.NewSOA(
		wirebb.MustParse("ns.example.com"),
		wirebb.MustParse("hm.example.com"),
		1, 0, 0, 0, 0,
	)
	require.NoError(t, err)
	require.Equal(t, time.Duration(0), soa.Refresh())
}

func TestCAAAccessors(t *testing.T) {
	t.Parallel()
	r, err := rdata.NewCAA(0x80, "issue", []byte("letsencrypt.org"))
	require.NoError(t, err)
	require.Equal(t, uint8(0x80), r.Flags())
	require.Equal(t, "issue", r.Tag())
	require.Equal(t, []byte("letsencrypt.org"), r.Value())
}
