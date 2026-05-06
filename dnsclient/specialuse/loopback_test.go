package specialuse_test

import (
	"testing"

	"github.com/lestrrat-go/acidns/dnsclient/specialuse"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/stretchr/testify/require"
)

func TestLoopbackForType(t *testing.T) {
	t.Parallel()
	v4 := specialuse.LoopbackForType(rrtype.A)
	require.Len(t, v4, 1)
	require.Equal(t, "127.0.0.1", v4[0].String())

	v6 := specialuse.LoopbackForType(rrtype.AAAA)
	require.Len(t, v6, 1)
	require.Equal(t, "::1", v6[0].String())

	require.Empty(t, specialuse.LoopbackForType(rrtype.MX))
	require.Empty(t, specialuse.LoopbackForType(rrtype.TXT))
}

func TestForInvalidName(t *testing.T) {
	t.Parallel()
	require.Equal(t, specialuse.Pass, specialuse.For(dnsname.Name{}))
}
