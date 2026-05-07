package validator_test

import (
	"testing"

	"github.com/lestrrat-go/acidns/dnssec/validator"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/stretchr/testify/require"
)

func TestNTAStoreCovers(t *testing.T) {
	t.Parallel()
	s := validator.NewNTAStore(wire.MustParseName("de"))
	require.True(t, s.Covers(wire.MustParseName("de")))
	require.True(t, s.Covers(wire.MustParseName("denic.de")))
	require.True(t, s.Covers(wire.MustParseName("foo.bar.de")))
	require.False(t, s.Covers(wire.MustParseName("example.com")))
}

func TestNTAStoreAddRemove(t *testing.T) {
	t.Parallel()
	s := validator.NewNTAStore()
	require.True(t, s.Add(wire.MustParseName("test.example")))
	require.False(t, s.Add(wire.MustParseName("test.example")), "second add returns false")
	require.True(t, s.Covers(wire.MustParseName("a.test.example")))
	require.True(t, s.Remove(wire.MustParseName("test.example")))
	require.False(t, s.Covers(wire.MustParseName("a.test.example")))
}

func TestValidatorNTAShortCircuits(t *testing.T) {
	t.Parallel()
	s := validator.NewNTAStore(wire.MustParseName("de"))
	v := validator.New(validator.Options{NTAs: s})

	// Even though we provide nothing else, the NTA causes Indeterminate.
	res, err := v.VerifyDelegation(wire.MustParseName("denic.de"), nil, nil)
	require.NoError(t, err)
	require.Equal(t, validator.Indeterminate, res)
}

func TestValidatorEmptyChainIsInsecure(t *testing.T) {
	t.Parallel()
	v := validator.New(validator.Options{})
	res, err := v.VerifyDelegation(wire.MustParseName("example.com"), nil, nil)
	require.NoError(t, err)
	require.Equal(t, validator.Insecure, res)
}
