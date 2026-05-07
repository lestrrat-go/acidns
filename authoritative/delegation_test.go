package authoritative_test

import (
	"strings"
	"testing"

	"github.com/lestrrat-go/acidns/authoritative"
	"github.com/lestrrat-go/acidns/dnszone"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
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

func newDelegationAuth(t *testing.T) authoritative.Authoritative {
	t.Helper()
	z, err := dnszone.Parse(strings.NewReader(delegationZone))
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
