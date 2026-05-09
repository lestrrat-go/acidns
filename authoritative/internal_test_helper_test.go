package authoritative

import (
	"testing"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/stretchr/testify/require"
)

func mustEDNS(t *testing.T, b wire.EDNSBuilder) wire.EDNS {
	t.Helper()
	e, err := b.Build()
	require.NoError(t, err)
	return e
}
