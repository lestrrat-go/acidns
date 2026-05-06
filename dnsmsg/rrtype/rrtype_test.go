package rrtype_test

import (
	"testing"

	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/stretchr/testify/require"
)

func TestType(t *testing.T) {
	t.Parallel()

	cases := []struct {
		t    rrtype.Type
		name string
	}{
		{rrtype.A, "A"},
		{rrtype.NS, "NS"},
		{rrtype.CNAME, "CNAME"},
		{rrtype.SOA, "SOA"},
		{rrtype.PTR, "PTR"},
		{rrtype.MX, "MX"},
		{rrtype.TXT, "TXT"},
		{rrtype.AAAA, "AAAA"},
		{rrtype.SRV, "SRV"},
		{rrtype.OPT, "OPT"},
		{rrtype.ANY, "ANY"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.name, tc.t.String())
			parsed, ok := rrtype.Parse(tc.name)
			require.True(t, ok)
			require.Equal(t, tc.t, parsed)
		})
	}
}

func TestUnknownType(t *testing.T) {
	t.Parallel()
	require.Equal(t, "TYPE65000", rrtype.Type(65000).String())
	_, ok := rrtype.Parse("TYPE65000")
	require.True(t, ok)
}

func TestClass(t *testing.T) {
	t.Parallel()
	require.Equal(t, "IN", rrtype.ClassIN.String())
	require.Equal(t, "CH", rrtype.ClassCH.String())
	require.Equal(t, "CLASS123", rrtype.Class(123).String())
}
