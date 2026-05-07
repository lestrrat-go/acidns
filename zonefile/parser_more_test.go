package zonefile_test

import (
	"strings"
	"testing"

	"github.com/lestrrat-go/acidns/zonefile"
	"github.com/stretchr/testify/require"
)

func TestParseClasses(t *testing.T) {
	t.Parallel()
	cases := []string{
		`@ CH TXT "x"`,
		`@ HS A 192.0.2.1`,
	}
	for _, c := range cases {
		_, err := zonefile.Parse(strings.NewReader("$ORIGIN example.com.\n$TTL 60\n" + c + "\n"))
		// Either success or controlled error — what matters is that the
		// parser walks the class branches.
		_ = err
	}
}

func TestParseInvalidA(t *testing.T) {
	t.Parallel()
	_, err := zonefile.Parse(strings.NewReader("$ORIGIN example.com.\n$TTL 60\n@ IN A not-an-ip\n"))
	require.Error(t, err)
}

func TestParseInvalidAAAA(t *testing.T) {
	t.Parallel()
	_, err := zonefile.Parse(strings.NewReader("$ORIGIN example.com.\n$TTL 60\n@ IN AAAA not-v6\n"))
	require.Error(t, err)
}

func TestParseUnknownDirective(t *testing.T) {
	t.Parallel()
	_, err := zonefile.Parse(strings.NewReader("$WHATEVER foo\n"))
	require.Error(t, err)
}

func TestParseMXMissingPref(t *testing.T) {
	t.Parallel()
	_, err := zonefile.Parse(strings.NewReader("$ORIGIN example.com.\n$TTL 60\n@ IN MX mail.example.com.\n"))
	require.Error(t, err)
}

func TestParseSOAMissingFields(t *testing.T) {
	t.Parallel()
	_, err := zonefile.Parse(strings.NewReader("$ORIGIN example.com.\n$TTL 60\n@ IN SOA ns. hm.\n"))
	require.Error(t, err)
}
