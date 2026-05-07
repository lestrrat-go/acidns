package zonefile_test

import (
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/zonefile"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

func TestParseSimple(t *testing.T) {
	t.Parallel()
	in := `$ORIGIN example.com.
$TTL 3600
@   IN  SOA  ns1.example.com. hostmaster.example.com. (
    2024010100  ; serial
    7200        ; refresh
    3600        ; retry
    1209600     ; expire
    3600        ; minimum
)
@   IN  NS   ns1.example.com.
@   IN  NS   ns2.example.com.
@   IN  A    192.0.2.1
www IN  A    192.0.2.2
www IN  AAAA 2001:db8::1
mail IN MX   10 mail.example.com.
mail IN A    192.0.2.3
    IN  TXT  "v=spf1" "-all"
`
	z, err := zonefile.Parse(strings.NewReader(in))
	require.NoError(t, err)
	require.Equal(t, "example.com.", z.Origin().String())

	rrs := z.Records()
	require.GreaterOrEqual(t, len(rrs), 8)

	soaRR, ok := findRR(rrs, "example.com.", rrtype.SOA)
	require.True(t, ok)
	soa := soaRR.RData().(rdata.SOA)
	require.Equal(t, uint32(2024010100), soa.Serial())
	require.Equal(t, 3600*time.Second, soa.Minimum())
	require.Equal(t, 7200*time.Second, soa.Refresh())

	wwwRR, ok := findRR(rrs, "www.example.com.", rrtype.A)
	require.True(t, ok)
	require.Equal(t, "192.0.2.2", wwwRR.RData().(rdata.A).Addr().String())

	wwwAAAA, ok := findRR(rrs, "www.example.com.", rrtype.AAAA)
	require.True(t, ok)
	require.Equal(t, "2001:db8::1", wwwAAAA.RData().(rdata.AAAA).Addr().String())

	mxRR, ok := findRR(rrs, "mail.example.com.", rrtype.MX)
	require.True(t, ok)
	mx := mxRR.RData().(rdata.MX)
	require.Equal(t, uint16(10), mx.Preference())

	// Blank owner uses previous owner: TXT goes on mail.example.com.
	txtRR, ok := findRR(rrs, "mail.example.com.", rrtype.TXT)
	require.True(t, ok)
	require.Equal(t, []string{"v=spf1", "-all"}, txtRR.RData().(rdata.TXT).Strings())
}

func TestParseDefaultsAndComments(t *testing.T) {
	t.Parallel()
	in := `; top comment
$ORIGIN example.com.
$TTL 600
@ IN A 192.0.2.10  ; trailing
`
	z, err := zonefile.Parse(strings.NewReader(in))
	require.NoError(t, err)

	rr, ok := findRR(z.Records(), "example.com.", rrtype.A)
	require.True(t, ok)
	require.Equal(t, 600*time.Second, rr.TTL())
}

func TestParseRelativeName(t *testing.T) {
	t.Parallel()
	in := `$ORIGIN example.com.
$TTL 60
sub.dom IN A 192.0.2.20
`
	z, err := zonefile.Parse(strings.NewReader(in))
	require.NoError(t, err)
	rr, ok := findRR(z.Records(), "sub.dom.example.com.", rrtype.A)
	require.True(t, ok)
	require.Equal(t, "192.0.2.20", rr.RData().(rdata.A).Addr().String())
}

func TestParseExplicitTTL(t *testing.T) {
	t.Parallel()
	in := `$ORIGIN example.com.
@ 120 IN A 192.0.2.30
`
	z, err := zonefile.Parse(strings.NewReader(in))
	require.NoError(t, err)
	rr, ok := findRR(z.Records(), "example.com.", rrtype.A)
	require.True(t, ok)
	require.Equal(t, 120*time.Second, rr.TTL())
}

func TestParseErrors(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"no origin":      "@ 60 IN A 192.0.2.1\n",
		"missing ttl":    "$ORIGIN example.com.\n@ IN A 192.0.2.1\n",
		"bad type":       "$ORIGIN example.com.\n$TTL 60\n@ IN BOGUS data\n",
		"bad ip":         "$ORIGIN example.com.\n$TTL 60\n@ IN A 999.999.999.999\n",
		"unbalanced par": "$ORIGIN example.com.\n$TTL 60\n@ IN SOA a b ( 1 2 3 4 5\n",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := zonefile.Parse(strings.NewReader(in))
			require.Error(t, err)
		})
	}
}

func findRR(rrs []wire.Record, name string, t rrtype.Type) (wire.Record, bool) {
	for _, r := range rrs {
		if r.Name().String() == name && r.Type() == t {
			return r, true
		}
	}
	return nil, false
}
