package rrtype_test

import (
	"testing"

	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

func TestClassString(t *testing.T) {
	t.Parallel()
	require.Equal(t, "IN", rrtype.ClassIN.String())
	require.Equal(t, "CH", rrtype.ClassCH.String())
	require.Equal(t, "HS", rrtype.ClassHS.String())
	require.Equal(t, "NONE", rrtype.ClassNONE.String())
	require.Equal(t, "ANY", rrtype.ClassANY.String())
	require.Equal(t, "CLASS999", rrtype.Class(999).String())
}

func TestParseRejectsBadType(t *testing.T) {
	t.Parallel()
	_, ok := rrtype.Parse("NOPE")
	require.False(t, ok)
	_, ok = rrtype.Parse("TYPEnotanumber")
	require.False(t, ok)
}

func TestParseGenericForm(t *testing.T) {
	t.Parallel()
	got, ok := rrtype.Parse("TYPE65000")
	require.True(t, ok)
	require.Equal(t, rrtype.Type(65000), got)
}
