package dnszone_test

import (
	"strings"
	"testing"

	"github.com/lestrrat-go/acidns/dnszone"
	"github.com/stretchr/testify/require"
)

func TestParseAllRRTypes(t *testing.T) {
	t.Parallel()
	src := `$ORIGIN example.com.
$TTL 60
@   IN  SOA  ns. hm. ( 1 7200 3600 1209600 60 )
@   IN  NS   ns1.example.com.
ns1 IN  A    192.0.2.10
v6  IN  AAAA 2001:db8::1
www IN  CNAME other.example.com.
ptr IN  PTR  host.example.com.
mx  IN  MX   10 mail.example.com.
txt IN  TXT  "hello" "world"
`
	z, err := dnszone.Parse(strings.NewReader(src))
	require.NoError(t, err)
	require.Greater(t, len(z.Records()), 5)
}

func TestParseQuotedTXT(t *testing.T) {
	t.Parallel()
	src := `$ORIGIN example.com.
$TTL 60
@ IN TXT "with \"escaped\" quotes"
`
	_, err := dnszone.Parse(strings.NewReader(src))
	require.NoError(t, err)
}

func TestParseInvalidNS(t *testing.T) {
	t.Parallel()
	_, err := dnszone.Parse(strings.NewReader("$ORIGIN example.com.\n$TTL 60\n@ IN NS not a name\n"))
	require.Error(t, err)
}

func TestParseUnknownType(t *testing.T) {
	t.Parallel()
	_, err := dnszone.Parse(strings.NewReader("$ORIGIN example.com.\n$TTL 60\n@ IN UNKNOWNRRTYPE foo\n"))
	require.Error(t, err)
}
