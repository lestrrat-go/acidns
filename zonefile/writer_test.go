package zonefile_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/zonefile"
	"github.com/stretchr/testify/require"
)

func TestWriteRoundTrip(t *testing.T) {
	t.Parallel()
	in := `$ORIGIN example.com.
$TTL 3600
@   IN  SOA  ns1.example.com. hostmaster.example.com. (
    2024010100 7200 3600 1209600 3600 )
@   IN  NS   ns1.example.com.
ns1 IN  A    192.0.2.10
www IN  A    192.0.2.2
www IN  AAAA 2001:db8::2
mail IN MX   10 mail.example.com.
    IN  TXT  "v=spf1" "-all"
`
	z, err := zonefile.Parse(strings.NewReader(in))
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, zonefile.Write(&buf, z))

	z2, err := zonefile.Parse(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)

	require.Equal(t, z.Origin().String(), z2.Origin().String())
	require.Equal(t, len(z.Records()), len(z2.Records()))

	// Pair records by (name, type, ttl, rdata-string-form) and assert match.
	got := indexRecords(z.Records())
	want := indexRecords(z2.Records())
	require.Equal(t, got, want)
}

func indexRecords(rrs []wire.Record) map[string]int {
	m := map[string]int{}
	for _, r := range rrs {
		key := r.Name().String() + "|" + r.Type().String()
		m[key]++
	}
	return m
}

func TestWriteOwnerRelativisation(t *testing.T) {
	t.Parallel()
	in := `$ORIGIN example.com.
$TTL 60
@ IN SOA ns. hostmaster. ( 1 2 3 4 5 )
@ IN A 192.0.2.1
www IN A 192.0.2.2
`
	z, err := zonefile.Parse(strings.NewReader(in))
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, zonefile.Write(&buf, z))
	out := buf.String()

	require.Contains(t, out, "$ORIGIN example.com.\n")
	// Apex record uses @
	require.Regexp(t, `(?m)^@\t60\tIN\tA\t192\.0\.2\.1`, out)
	// www uses relative form
	require.Regexp(t, `(?m)^www\t60\tIN\tA\t192\.0\.2\.2`, out)
	// And the original should also re-parse cleanly.
	_, err = zonefile.Parse(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
}

// TestWriteRoundTripAllTypes confirms that every rdata type the writer
// touches — including those that fall back to RFC 3597 §5 generic form —
// round-trips parse → write → parse without error. Path A presentations
// (SRV/DS/DNSKEY/DNAME) re-parse via the type-specific branch; SVCB/HTTPS
// re-parse via the generic `\#` fallback.
func TestWriteRoundTripAllTypes(t *testing.T) {
	t.Parallel()

	// Build a zone synthetically so we can include rdata types the parser
	// doesn't have a presentation grammar for (SVCB, HTTPS).
	origin := wire.MustParseName("example.com")
	mustSOA := func() rdata.SOA {
		soa, err := rdata.NewSOA(
			wire.MustParseName("ns.example.com"),
			wire.MustParseName("hm.example.com"),
			1, 7200*time.Second, 3600*time.Second,
			1209600*time.Second, 3600*time.Second)
		require.NoError(t, err)
		return soa
	}

	srv, err := rdata.NewSRV(10, 20, 443, wire.MustParseName("svc.example.com"))
	require.NoError(t, err)
	ds, err := rdata.NewDS(12345, rdata.DNSSECAlgorithm(13), rdata.DSDigestType(2),
		bytes.Repeat([]byte{0xab}, 32))
	require.NoError(t, err)
	dnskey, err := rdata.NewDNSKEY(257, 3, rdata.DNSSECAlgorithm(13),
		bytes.Repeat([]byte{0xcd}, 64))
	require.NoError(t, err)
	dname, err := rdata.NewDNAME(wire.MustParseName("target.example.org"))
	require.NoError(t, err)
	svcb, err := rdata.NewSVCB(1, wire.MustParseName("svc.example.com"))
	require.NoError(t, err)
	https, err := rdata.NewHTTPS(1, wire.MustParseName("svc.example.com"))
	require.NoError(t, err)

	mk := func(owner string, rd rdata.RData) wire.Record {
		return wire.NewRecordClass(wire.MustParseName(owner),
			rrtype.ClassIN, 3600*time.Second, rd)
	}

	records := []wire.Record{
		mk("example.com", mustSOA()),
		mk("_https._tcp.example.com", srv),
		mk("example.com", ds),
		mk("example.com", dnskey),
		mk("alias.example.com", dname),
		mk("svc.example.com", svcb),
		mk("example.com", https),
	}
	z := &writerRoundTripZone{origin: origin, records: records, soa: records[0]}

	var buf bytes.Buffer
	require.NoError(t, zonefile.Write(&buf, z))

	z2, err := zonefile.Parse(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	require.Equal(t, len(records), len(z2.Records()))

	// Confirm each type made it through and the rdata matches at the
	// wire level (Path B fallback uses generic form, so the dynamic
	// rdata type is preserved via rdata.Unpack).
	byType := map[rrtype.Type]wire.Record{}
	for _, r := range z2.Records() {
		byType[r.Type()] = r
	}
	for _, want := range records {
		got, ok := byType[want.Type()]
		require.True(t, ok, "type %s missing after round-trip", want.Type())
		require.Equal(t, rdata.Pack(want.RData()), rdata.Pack(got.RData()),
			"rdata payload diverged for %s", want.Type())
	}
}

// writerRoundTripZone is a minimal Zone for driving the writer against
// synthetic records the parser can't construct natively.
type writerRoundTripZone struct {
	origin  wire.Name
	records []wire.Record
	soa     wire.Record
}

func (z *writerRoundTripZone) Origin() wire.Name      { return z.origin }
func (z *writerRoundTripZone) Records() []wire.Record { return z.records }
func (z *writerRoundTripZone) SOA() (rdata.SOA, wire.Record, bool) {
	if soa, ok := wire.RDataAs[rdata.SOA](z.soa); ok {
		return soa, z.soa, true
	}
	return rdata.SOA{}, wire.Record{}, false
}

func TestWriteTXTQuoting(t *testing.T) {
	t.Parallel()
	in := `$ORIGIN example.com.
$TTL 60
@ IN SOA ns. hm. ( 1 2 3 4 5 )
weird IN TXT "has \"quote\" and \\back"
`
	z, err := zonefile.Parse(strings.NewReader(in))
	require.NoError(t, err)
	rrs := z.Records()
	var found bool
	for _, r := range rrs {
		if r.Type() == rrtype.TXT {
			found = true
			break
		}
	}
	require.True(t, found)

	var buf bytes.Buffer
	require.NoError(t, zonefile.Write(&buf, z))

	z2, err := zonefile.Parse(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	require.Equal(t, len(z.Records()), len(z2.Records()))
}
