package validator_test

import (
	"testing"

	"github.com/lestrrat-go/acidns/dnssec/validator"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

func TestIsCompactNXDOMAIN(t *testing.T) {
	t.Parallel()
	withNX := rdata.NewNSEC(wire.MustParseName("next.example.com"),
		[]rrtype.Type{rrtype.RRSIG, rrtype.NSEC, rrtype.NXNAME})
	require.True(t, validator.IsCompactNXDOMAIN(withNX))

	regular := rdata.NewNSEC(wire.MustParseName("next.example.com"),
		[]rrtype.Type{rrtype.A, rrtype.RRSIG, rrtype.NSEC})
	require.False(t, validator.IsCompactNXDOMAIN(regular))
}
