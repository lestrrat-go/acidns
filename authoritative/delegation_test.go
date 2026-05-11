package authoritative_test

import (
	"strings"
	"testing"

	"github.com/lestrrat-go/acidns/authoritative"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/zonefile"
	"github.com/stretchr/testify/require"
)

const delegationZone = `$ORIGIN example.com.
$TTL 3600
@   IN  SOA  ns1.example.com. hostmaster.example.com. (
    2024010100 7200 3600 1209600 3600 )
@   IN  NS   ns1.example.com.
ns1 IN  A    192.0.2.10
www IN  A    192.0.2.2

; Delegation of sub.example.com with in-bailiwick NS + glue.
sub        IN NS ns1.sub.example.com.
sub        IN NS ns2.sub.example.com.
ns1.sub    IN A  192.0.2.20
ns2.sub    IN A  192.0.2.21
ns2.sub    IN AAAA 2001:db8::20

; Delegation of out.example.com with out-of-bailiwick NS, no glue.
out IN NS ns1.elsewhere.example.org.
`

func newDelegationAuth(t *testing.T) *authoritative.Authoritative {
	t.Helper()
	z, err := zonefile.Parse(strings.NewReader(delegationZone))
	require.NoError(t, err)
	a, err := authoritative.New(authoritative.WithZone(z))
	require.NoError(t, err)
	return a
}

func TestDelegationReferralWithGlue(t *testing.T) {
	t.Parallel()
	a := newDelegationAuth(t)
	resp := ask(t, a, "host.sub.example.com", rrtype.A)

	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())
	require.False(t, resp.Flags().Authoritative(), "AA must be 0 for downward referrals")
	require.Equal(t, 0, len(resp.Answers()))

	// Authority: NS records of the delegation point.
	require.Equal(t, 2, len(resp.Authorities()))
	for _, r := range resp.Authorities() {
		require.Equal(t, rrtype.NS, r.Type())
		require.Equal(t, "sub.example.com.", r.Name().String())
	}

	// Additional: glue for both NS targets.
	require.Equal(t, 3, len(resp.Additionals()))
}

func TestDelegationOutOfBailiwickNoGlue(t *testing.T) {
	t.Parallel()
	a := newDelegationAuth(t)
	resp := ask(t, a, "host.out.example.com", rrtype.A)

	require.False(t, resp.Flags().Authoritative())
	require.Equal(t, 1, len(resp.Authorities()))
	require.Equal(t, 0, len(resp.Additionals()))
}

func TestDelegationAtPoint(t *testing.T) {
	t.Parallel()
	a := newDelegationAuth(t)
	// Querying the delegation point itself also returns a referral.
	resp := ask(t, a, "sub.example.com", rrtype.A)
	require.False(t, resp.Flags().Authoritative())
	require.Equal(t, 0, len(resp.Answers()))
	require.Equal(t, 2, len(resp.Authorities()))
}

func TestZoneApexNSIsAuthoritative(t *testing.T) {
	t.Parallel()
	a := newDelegationAuth(t)
	// NS records at the apex are NOT a delegation; they're the zone's own
	// authoritative NS RRSet.
	resp := ask(t, a, "example.com", rrtype.NS)
	require.True(t, resp.Flags().Authoritative())
	require.Equal(t, 1, len(resp.Answers()))
	require.Equal(t, rrtype.NS, resp.Answers()[0].Type())
}

func TestDelegationDoesNotShadowOutsideNames(t *testing.T) {
	t.Parallel()
	a := newDelegationAuth(t)
	// www.example.com is NOT under the sub delegation; normal lookup applies.
	resp := ask(t, a, "www.example.com", rrtype.A)
	require.True(t, resp.Flags().Authoritative())
	require.Equal(t, 1, len(resp.Answers()))
	require.Equal(t, "192.0.2.2", resp.Answers()[0].RData().(rdata.A).Addr().String())
}

// TestANYBelowDelegationReferralNotMinimalHINFO guards against the
// RFC 8482 minimal-ANY synthesiser claiming authority over a name in a
// delegated subzone. The synthesis must fire only AFTER findDelegation
// confirms the name is in-zone; otherwise the server would return AA=1
// with the parent zone's SOA for a name it has delegated away.
func TestANYBelowDelegationReferralNotMinimalHINFO(t *testing.T) {
	t.Parallel()
	a := newDelegationAuth(t)
	resp := ask(t, a, "host.sub.example.com", rrtype.ANY)

	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())
	require.False(t, resp.Flags().Authoritative(),
		"AA must be 0 for ANY against a name below a delegation")
	require.Equal(t, 0, len(resp.Answers()),
		"ANY below delegation must not synthesise an RFC 8482 HINFO")
	require.Equal(t, 2, len(resp.Authorities()),
		"ANY below delegation must return NS records of the delegation point")
	for _, r := range resp.Authorities() {
		require.Equal(t, rrtype.NS, r.Type())
		require.Equal(t, "sub.example.com.", r.Name().String())
	}
}

// TestANYInZoneStillSynthesisesMinimalHINFO ensures the gating fix does
// not regress the RFC 8482 path for names the server IS authoritative
// for: an ANY query for an in-zone name still collapses to the single
// synthetic HINFO answer with AA=1.
func TestANYInZoneStillSynthesisesMinimalHINFO(t *testing.T) {
	t.Parallel()
	a := newDelegationAuth(t)
	resp := ask(t, a, "host.example.com", rrtype.ANY)

	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())
	require.True(t, resp.Flags().Authoritative())
	require.Equal(t, 1, len(resp.Answers()))
	rec := resp.Answers()[0]
	require.Equal(t, rrtype.HINFO, rec.Type())
	hi, ok := wire.RDataAs[rdata.HINFO](rec)
	require.True(t, ok)
	require.Equal(t, "RFC8482", hi.CPU())
}
