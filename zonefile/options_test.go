package zonefile_test

import (
	"strings"
	"testing"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/zonefile"
	"github.com/stretchr/testify/require"
)

func TestParseWithOptions(t *testing.T) {
	t.Parallel()
	src := `@ IN A 192.0.2.1
www IN A 192.0.2.2
`
	z, err := zonefile.Parse(strings.NewReader(src),
		zonefile.WithOrigin(wire.MustParseName("example.com")),
		zonefile.WithDefaultTTL(300),
	)
	require.NoError(t, err)
	require.NotNil(t, z)
	require.Equal(t, "example.com.", z.Origin().String())
}
