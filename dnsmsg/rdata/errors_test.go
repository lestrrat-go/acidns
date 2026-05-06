package rdata_test

import (
	"testing"

	"github.com/lestrrat-go/acidns/dnsmsg/internal/wire"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/stretchr/testify/require"
)

// TestUnpackTruncations feeds short payloads to each rdata Unpack to drive
// the error branches. We don't care which error — just that one is returned.
func TestUnpackTruncations(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		t    rrtype.Type
		l    int // bytes available; unpacker will see fewer than rdlen
	}{
		{"A", rrtype.A, 2},
		{"AAAA", rrtype.AAAA, 5},
		{"CNAME", rrtype.CNAME, 0},
		{"NS", rrtype.NS, 0},
		{"PTR", rrtype.PTR, 0},
		{"MX", rrtype.MX, 1},
		{"SOA", rrtype.SOA, 1},
		{"SVCB", rrtype.SVCB, 1},
		{"DNSKEY", rrtype.DNSKEY, 1},
		{"DS", rrtype.DS, 1},
		{"RRSIG", rrtype.RRSIG, 1},
		{"NSEC3PARAM", rrtype.NSEC3PARAM, 1},
		{"SRV", rrtype.SRV, 1},
		{"NAPTR", rrtype.NAPTR, 1},
		{"SSHFP", rrtype.SSHFP, 1},
		{"TLSA", rrtype.TLSA, 1},
		{"CSYNC", rrtype.CSYNC, 1},
		{"AFSDB", rrtype.AFSDB, 1},
		{"X25", rrtype.X25, 0},
		{"ISDN", rrtype.ISDN, 0},
		{"RT", rrtype.RT, 1},
		{"RP", rrtype.RP, 0},
		{"LOC", rrtype.LOC, 0},
		{"APL", rrtype.APL, 1},
		{"IPSECKEY", rrtype.IPSECKEY, 0},
		{"HIP", rrtype.HIP, 1},
		{"NID", rrtype.NID, 1},
		{"L32", rrtype.L32, 1},
		{"L64", rrtype.L64, 1},
		{"LP", rrtype.LP, 1},
		{"EUI48", rrtype.EUI48, 0},
		{"EUI64", rrtype.EUI64, 0},
		{"URI", rrtype.URI, 1},
		{"ZONEMD", rrtype.ZONEMD, 1},
		{"CAA", rrtype.CAA, 0},
		{"TXT", rrtype.TXT, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := make([]byte, tc.l)
			u := wire.NewUnpacker(buf)
			// Pretend rdlen is much larger to trigger the bounds check.
			rdlen := tc.l + 100
			_, err := rdata.Unpack(tc.t, u, rdlen)
			require.Error(t, err)
		})
	}
}

func TestUnpackZeroRdlen(t *testing.T) {
	t.Parallel()
	u := wire.NewUnpacker(nil)
	got, err := rdata.Unpack(rrtype.A, u, 0)
	require.NoError(t, err)
	// rdata.Unknown is returned for zero-length rdata of any type.
	require.Equal(t, rrtype.A, got.Type())
}

func TestUnpackNegativeRdlen(t *testing.T) {
	t.Parallel()
	u := wire.NewUnpacker(nil)
	_, err := rdata.Unpack(rrtype.A, u, -1)
	require.Error(t, err)
}
