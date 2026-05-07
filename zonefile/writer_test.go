package zonefile_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/lestrrat-go/acidns/zonefile"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
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
