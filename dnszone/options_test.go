package dnszone_test

import (
	"strings"
	"testing"

	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/lestrrat-go/acidns/dnszone"
	"github.com/stretchr/testify/require"
)

func TestParseWithOptions(t *testing.T) {
	t.Parallel()
	src := `@ IN A 192.0.2.1
www IN A 192.0.2.2
`
	z, err := dnszone.Parse(strings.NewReader(src),
		dnszone.WithOrigin(dnsname.MustParse("example.com")),
		dnszone.WithDefaultTTL(300),
	)
	require.NoError(t, err)
	require.NotNil(t, z)
	require.Equal(t, "example.com.", z.Origin().String())
}
