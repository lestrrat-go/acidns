package classless_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnszone/classless"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

func TestBuildDelegationCNAMEsSlash27(t *testing.T) {
	t.Parallel()

	prefix := netip.MustParsePrefix("192.0.2.0/27")
	sub := wire.MustParseName("0-31.2.0.192.in-addr.arpa")
	recs, err := classless.BuildDelegationCNAMEs(prefix, sub, 3600*time.Second)
	require.NoError(t, err)
	require.Equal(t, 32, len(recs))

	first := recs[0]
	require.Equal(t, rrtype.CNAME, first.Type())
	require.Equal(t, "0.2.0.192.in-addr.arpa.", first.Name().String())
	require.Equal(t, "0.0-31.2.0.192.in-addr.arpa.",
		first.RData().(rdata.CNAME).Target().String())

	last := recs[31]
	require.Equal(t, "31.2.0.192.in-addr.arpa.", last.Name().String())
}

func TestBuildDelegationCNAMEsSlash25(t *testing.T) {
	t.Parallel()
	prefix := netip.MustParsePrefix("198.51.100.0/25")
	sub := wire.MustParseName("0-127.100.51.198.in-addr.arpa")
	recs, err := classless.BuildDelegationCNAMEs(prefix, sub, time.Minute)
	require.NoError(t, err)
	require.Equal(t, 128, len(recs))
}

func TestBuildDelegationCNAMEsRejectsTooLarge(t *testing.T) {
	t.Parallel()
	_, err := classless.BuildDelegationCNAMEs(
		netip.MustParsePrefix("10.0.0.0/24"),
		wire.MustParseName("foo.in-addr.arpa"), time.Minute)
	require.Error(t, err)
}

func TestBuildDelegationCNAMEsRejectsIPv6(t *testing.T) {
	t.Parallel()
	_, err := classless.BuildDelegationCNAMEs(
		netip.MustParsePrefix("2001:db8::/64"),
		wire.MustParseName("foo.ip6.arpa"), time.Minute)
	require.Error(t, err)
}
