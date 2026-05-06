package validator_test

import (
	"testing"

	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/lestrrat-go/acidns/dnssec/validator"
	"github.com/stretchr/testify/require"
)

func TestIsCompactNXDOMAIN(t *testing.T) {
	t.Parallel()
	withNX := rdata.NewNSEC(dnsname.MustParse("next.example.com"),
		[]rrtype.Type{rrtype.RRSIG, rrtype.NSEC, rrtype.NXNAME})
	require.True(t, validator.IsCompactNXDOMAIN(withNX))

	regular := rdata.NewNSEC(dnsname.MustParse("next.example.com"),
		[]rrtype.Type{rrtype.A, rrtype.RRSIG, rrtype.NSEC})
	require.False(t, validator.IsCompactNXDOMAIN(regular))
}
