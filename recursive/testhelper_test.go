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

// mustEntry resolves the (Entry, error) return shape of
// EntryBuilder.Build for tests that build well-formed entries.
func mustEntry(t *testing.T, b *recursive.EntryBuilder) recursive.Entry {
	t.Helper()
	e, err := b.Build()
	require.NoError(t, err)
	return e
}
