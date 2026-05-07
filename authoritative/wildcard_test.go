package authoritative_test

import (
	"strings"
	"testing"

	"github.com/lestrrat-go/acidns/authoritative"
	"github.com/lestrrat-go/acidns/zonefile"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

const wildcardZone = `$ORIGIN example.com.
$TTL 3600
@   IN  SOA  ns1.example.com. hostmaster.example.com. (
    2024010100 7200 3600 1209600 3600 )
@   IN  NS   ns1.example.com.
ns1 IN  A    192.0.2.10
*   IN  A    192.0.2.50
*   IN  TXT  "wildcard"
sub.deep IN A 192.0.2.99
`

func newWildcardAuth(t *testing.T) authoritative.Authoritative {
	t.Helper()
	z, err := zonefile.Parse(strings.NewReader(wildcardZone))
	require.NoError(t, err)
	a, err := authoritative.New(authoritative.WithZone(z))
	require.NoError(t, err)
	return a
}

func TestWildcardMatch(t *testing.T) {
	t.Parallel()
	a := newWildcardAuth(t)
	resp := ask(t, a, "anything.example.com", rrtype.A)
	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())
	require.Equal(t, 1, len(resp.Answers()))
	got := resp.Answers()[0]
	require.Equal(t, "anything.example.com.", got.Name().String(),
		"wildcard answer's owner is rewritten to QNAME")
	require.Equal(t, "192.0.2.50", got.RData().(rdata.A).Addr().String())
}

func TestWildcardTypeMiss(t *testing.T) {
	t.Parallel()
	a := newWildcardAuth(t)
	// Wildcard has A and TXT but not AAAA — query for AAAA → NODATA.
	resp := ask(t, a, "anything.example.com", rrtype.AAAA)
	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())
	require.Equal(t, 0, len(resp.Answers()))
	require.Equal(t, 1, len(resp.Authorities()))
	require.Equal(t, rrtype.SOA, resp.Authorities()[0].Type())
}

func TestExactMatchBeatsWildcard(t *testing.T) {
	t.Parallel()
	a := newWildcardAuth(t)
	// ns1 has its own A; wildcard must NOT shadow it.
	resp := ask(t, a, "ns1.example.com", rrtype.A)
	require.Equal(t, "192.0.2.10", resp.Answers()[0].RData().(rdata.A).Addr().String())
}

func TestWildcardBlockedByEmptyNonTerminal(t *testing.T) {
	t.Parallel()
	a := newWildcardAuth(t)
	// "deep.example.com" is an empty non-terminal (ancestor of sub.deep).
	// "weird.deep.example.com" should NOT match *.example.com — closest
	// encloser is deep.example.com, and *.deep.example.com doesn't exist
	// → NXDOMAIN.
	resp := ask(t, a, "weird.deep.example.com", rrtype.A)
	require.Equal(t, wire.RCODENXDomain, resp.Flags().RCODE())
}

func TestEmptyNonTerminalNODATA(t *testing.T) {
	t.Parallel()
	a := newWildcardAuth(t)
	// "deep.example.com" itself — exists as empty non-terminal — NODATA.
	resp := ask(t, a, "deep.example.com", rrtype.A)
	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())
	require.Equal(t, 0, len(resp.Answers()))
	require.Equal(t, 1, len(resp.Authorities()))
}
