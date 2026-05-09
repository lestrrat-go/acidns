package acidns_test

import (
	"testing"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/stretchr/testify/require"
)

// mustEDNS is the test-package shorthand for the (EDNS, error) return
// shape of wire.EDNSBuilder.Build. Tests that build well-formed EDNS
// payloads do not expect the construction to fail.
func mustEDNS(t *testing.T, b wire.EDNSBuilder) wire.EDNS {
	t.Helper()
	e, err := b.Build()
	require.NoError(t, err)
	return e
}
