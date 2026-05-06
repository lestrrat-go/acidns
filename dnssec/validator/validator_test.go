package validator_test

import (
	"testing"

	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/lestrrat-go/acidns/dnssec/validator"
	"github.com/stretchr/testify/require"
)

func TestNTAStoreCovers(t *testing.T) {
	t.Parallel()
	s := validator.NewNTAStore(dnsname.MustParse("de"))
	require.True(t, s.Covers(dnsname.MustParse("de")))
	require.True(t, s.Covers(dnsname.MustParse("denic.de")))
	require.True(t, s.Covers(dnsname.MustParse("foo.bar.de")))
	require.False(t, s.Covers(dnsname.MustParse("example.com")))
}

func TestNTAStoreAddRemove(t *testing.T) {
	t.Parallel()
	s := validator.NewNTAStore()
	require.True(t, s.Add(dnsname.MustParse("test.example")))
	require.False(t, s.Add(dnsname.MustParse("test.example")), "second add returns false")
	require.True(t, s.Covers(dnsname.MustParse("a.test.example")))
	require.True(t, s.Remove(dnsname.MustParse("test.example")))
	require.False(t, s.Covers(dnsname.MustParse("a.test.example")))
}

func TestValidatorNTAShortCircuits(t *testing.T) {
	t.Parallel()
	s := validator.NewNTAStore(dnsname.MustParse("de"))
	v := validator.New(validator.Options{NTAs: s})

	// Even though we provide nothing else, the NTA causes Indeterminate.
	res, err := v.VerifyDelegation(dnsname.MustParse("denic.de"), nil, nil)
	require.NoError(t, err)
	require.Equal(t, validator.Indeterminate, res)
}

func TestValidatorEmptyChainIsInsecure(t *testing.T) {
	t.Parallel()
	v := validator.New(validator.Options{})
	res, err := v.VerifyDelegation(dnsname.MustParse("example.com"), nil, nil)
	require.NoError(t, err)
	require.Equal(t, validator.Insecure, res)
}
