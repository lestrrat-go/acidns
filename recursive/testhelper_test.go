package recursive_test

import (
	"testing"

	"github.com/lestrrat-go/acidns/recursive"
	"github.com/stretchr/testify/require"
)

// mustRecursive is the test-package shorthand for the (Recursive, error)
// return shape of recursive.New. Tests that exercise the resolver under
// safe option combinations want a single-line construction.
func mustRecursive(t *testing.T, opts ...recursive.Option) recursive.Recursive {
	t.Helper()
	r, err := recursive.New(opts...)
	require.NoError(t, err)
	return r
}
