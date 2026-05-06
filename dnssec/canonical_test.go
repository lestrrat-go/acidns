package dnssec_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/lestrrat-go/acidns/dnssec"
	"github.com/stretchr/testify/require"
)

func TestSignedDataAcrossRDataTypes(t *testing.T) {
	t.Parallel()

	makeRRSIG := func(typ rrtype.Type, labels uint8) rdata.RRSIG {
		return rdata.NewRRSIG(typ, rdata.AlgED25519, labels,
			time.Hour, time.Now().Add(time.Hour), time.Now().Add(-time.Hour),
			1, dnsname.MustParse("example.com"), nil)
	}

	cases := []struct {
		name string
		set  []dnsmsg.Record
		typ  rrtype.Type
	}{
		{
			"NS",
			[]dnsmsg.Record{
				dnsmsg.NewRecord(dnsname.MustParse("example.com"), time.Hour,
					rdata.NewNS(dnsname.MustParse("ns1.example.com"))),
			},
			rrtype.NS,
		},
		{
			"CNAME",
			[]dnsmsg.Record{
				dnsmsg.NewRecord(dnsname.MustParse("a.example.com"), time.Hour,
					rdata.NewCNAME(dnsname.MustParse("b.example.com"))),
			},
			rrtype.CNAME,
		},
		{
			"PTR",
			[]dnsmsg.Record{
				dnsmsg.NewRecord(dnsname.MustParse("1.2.0.192.in-addr.arpa"), time.Hour,
					rdata.NewPTR(dnsname.MustParse("host.example.com"))),
			},
			rrtype.PTR,
		},
		{
			"SOA",
			[]dnsmsg.Record{
				dnsmsg.NewRecord(dnsname.MustParse("example.com"), time.Hour,
					rdata.NewSOA(
						dnsname.MustParse("ns.example.com"),
						dnsname.MustParse("hm.example.com"),
						1, time.Hour, time.Hour, time.Hour, time.Hour,
					)),
			},
			rrtype.SOA,
		},
		{
			"MX",
			[]dnsmsg.Record{
				dnsmsg.NewRecord(dnsname.MustParse("example.com"), time.Hour,
					rdata.NewMX(10, dnsname.MustParse("mx.example.com"))),
			},
			rrtype.MX,
		},
		{
			"A_unknown_default",
			[]dnsmsg.Record{
				dnsmsg.NewRecord(dnsname.MustParse("example.com"), time.Hour,
					rdata.NewA(netip.MustParseAddr("192.0.2.1"))),
			},
			rrtype.A,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
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
	set := []dnsmsg.Record{
		dnsmsg.NewRecord(dnsname.MustParse("foo.bar.example.com"), time.Hour,
			rdata.NewA(netip.MustParseAddr("192.0.2.1"))),
	}
	rrsig := rdata.NewRRSIG(rrtype.A, rdata.AlgED25519, 2,
		time.Hour, time.Now().Add(time.Hour), time.Now().Add(-time.Hour),
		1, dnsname.MustParse("example.com"), nil)
	out, err := dnssec.SignedData(set, rrsig)
	require.NoError(t, err)
	require.NotEmpty(t, out)
}

func TestSignedDataEmptySetErrors(t *testing.T) {
	t.Parallel()
	rrsig := rdata.NewRRSIG(rrtype.A, rdata.AlgED25519, 1,
		time.Hour, time.Now().Add(time.Hour), time.Now().Add(-time.Hour),
		1, dnsname.MustParse("example.com"), nil)
	_, err := dnssec.SignedData(nil, rrsig)
	require.Error(t, err)
}
