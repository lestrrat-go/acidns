package recursive_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/recursive"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// TestRecursiveSatisfiesResolver pins the interface satisfaction so a
// future change to acidns.Resolver that recursive.Recursive forgets to
// implement breaks the build instead of silently breaking LookupHost.
func TestRecursiveSatisfiesResolver(t *testing.T) {
	t.Parallel()
	var _ acidns.Resolver = (*recursive.Recursive)(nil)
}

// TestRecursiveResolveAnswer drives Recursive.Resolve through a typed
// query and asserts the *acidns.Answer is shaped correctly (matched
// records, raw response with RA=1, no RCodeError on NoError).
func TestRecursiveResolveAnswer(t *testing.T) {
	t.Parallel()

	childAddr := startAuth(t, `$ORIGIN example.com.
$TTL 60
@   IN  SOA  ns1.example.com. hm.example.com. ( 1 2 3 4 5 )
@   IN  NS   ns1.example.com.
ns1 IN  A    192.0.2.10
www IN  A    192.0.2.42
`)
	r := mustRecursive(t, recursive.WithRoots(childAddr))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	ans, err := r.Resolve(ctx, wire.MustParseName("www.example.com"), rrtype.A)
	require.NoError(t, err)
	require.NotNil(t, ans)
	require.Equal(t, 1, len(ans.Records()))
	a, ok := wire.RDataAs[rdata.A](ans.Records()[0])
	require.True(t, ok)
	require.Equal(t, "192.0.2.42", a.Addr().String())

	raw := ans.Raw()
	require.True(t, raw.Flags().Response())
	require.True(t, raw.Flags().RecursionAvailable())
	require.Equal(t, wire.RCODENoError, raw.Flags().RCODE())
}

// TestRecursiveResolveNXDOMAIN asserts the RCodeError contract:
// non-NoError responses surface as *acidns.RCodeError carrying the
// answer.
func TestRecursiveResolveNXDOMAIN(t *testing.T) {
	t.Parallel()

	childAddr := startAuth(t, `$ORIGIN example.com.
$TTL 60
@   IN  SOA  ns1.example.com. hm.example.com. ( 1 2 3 4 5 )
@   IN  NS   ns1.example.com.
ns1 IN  A    192.0.2.10
`)
	r := mustRecursive(t, recursive.WithRoots(childAddr))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	ans, err := r.Resolve(ctx, wire.MustParseName("missing.example.com"), rrtype.A)
	require.Nil(t, ans)
	var rce *acidns.RCodeError
	require.True(t, errors.As(err, &rce), "expected RCodeError, got %T %v", err, err)
	require.Equal(t, wire.RCODENXDomain, rce.Code())
	require.NotNil(t, rce.Answer())
	require.True(t, rce.Answer().Raw().Flags().Response())
}

// TestRecursiveSearchListIsEmpty pins that Recursive does not carry a
// search list — calling LookupHost against a Recursive resolves the
// name as-given without suffix expansion.
func TestRecursiveSearchListIsEmpty(t *testing.T) {
	t.Parallel()
	r := mustRecursive(t)
	require.Nil(t, r.SearchList())
	require.Equal(t, 0, r.Ndots())
}
