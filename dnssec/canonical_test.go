package dnssec_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnssec"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

func TestSignedDataAcrossRDataTypes(t *testing.T) {
	t.Parallel()

	makeRRSIG := func(typ rrtype.Type, labels uint8) rdata.RRSIG {
		return rdata.NewRRSIG(typ, rdata.AlgED25519, labels,
			time.Hour, time.Now().Add(time.Hour), time.Now().Add(-time.Hour),
			1, wire.MustParseName("example.com"), nil)
	}

	cases := []struct {
		name string
		set  []wire.Record
		typ  rrtype.Type
	}{
		{
			"NS",
			[]wire.Record{
				wire.NewRecord(wire.MustParseName("example.com"), time.Hour,
					rdata.MustNewNS(wire.MustParseName("ns1.example.com"))),
			},
			rrtype.NS,
		},
		{
			"CNAME",
			[]wire.Record{
				wire.NewRecord(wire.MustParseName("a.example.com"), time.Hour,
					rdata.MustNewCNAME(wire.MustParseName("b.example.com"))),
			},
			rrtype.CNAME,
		},
		{
			"PTR",
			[]wire.Record{
				wire.NewRecord(wire.MustParseName("1.2.0.192.in-addr.arpa"), time.Hour,
					rdata.MustNewPTR(wire.MustParseName("host.example.com"))),
			},
			rrtype.PTR,
		},
		{
			"SOA",
			[]wire.Record{
				wire.NewRecord(wire.MustParseName("example.com"), time.Hour,
					rdata.MustNewSOA(
						wire.MustParseName("ns.example.com"),
						wire.MustParseName("hm.example.com"),
						1, time.Hour, time.Hour, time.Hour, time.Hour,
					)),
			},
			rrtype.SOA,
		},
		{
			"MX",
			[]wire.Record{
				wire.NewRecord(wire.MustParseName("example.com"), time.Hour,
					rdata.MustNewMX(10, wire.MustParseName("mx.example.com"))),
			},
			rrtype.MX,
		},
		{
			"A_unknown_default",
			[]wire.Record{
				wire.NewRecord(wire.MustParseName("example.com"), time.Hour,
					rdata.MustNewA(netip.MustParseAddr("192.0.2.1"))),
			},
			rrtype.A,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			rrsig := makeRRSIG(c.typ, uint8(c.set[0].Name().NumLabels()))
			out, err := dnssec.SignedData(c.set, rrsig)
			require.NoError(t, err)
			require.NotEmpty(t, out)
		})
	}
}

func TestSignedDataWildcardOwner(t *testing.T) {
	t.Parallel()
	// owner has 4 labels but rrsig.Labels=2 → wildcard reconstruction
	// would walk back two levels.
	set := []wire.Record{
		wire.NewRecord(wire.MustParseName("foo.bar.example.com"), time.Hour,
			rdata.MustNewA(netip.MustParseAddr("192.0.2.1"))),
	}
	rrsig := rdata.NewRRSIG(rrtype.A, rdata.AlgED25519, 2,
		time.Hour, time.Now().Add(time.Hour), time.Now().Add(-time.Hour),
		1, wire.MustParseName("example.com"), nil)
	out, err := dnssec.SignedData(set, rrsig)
	require.NoError(t, err)
	require.NotEmpty(t, out)
}

func TestSignedDataEmptySetErrors(t *testing.T) {
	t.Parallel()
	rrsig := rdata.NewRRSIG(rrtype.A, rdata.AlgED25519, 1,
		time.Hour, time.Now().Add(time.Hour), time.Now().Add(-time.Hour),
		1, wire.MustParseName("example.com"), nil)
	_, err := dnssec.SignedData(nil, rrsig)
	require.Error(t, err)
}
