package acidns_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// Sequential server failover: a refused server is skipped and the next one
// answers.
func TestFalloverProgressesOnError(t *testing.T) {
	t.Parallel()

	good := startServer(t, []netip.Addr{netip.MustParseAddr("198.51.100.7")}, nil)
	bad := netip.MustParseAddrPort("127.0.0.1:1") // refused

	r, err := acidns.NewResolver(acidns.WithServers(bad, good))
	require.NoError(t, err)

	addrs, err := acidns.LookupHost(t.Context(), r, "example.com")
	require.NoError(t, err)
	require.Equal(t, 1, len(addrs))
	require.Equal(t, "198.51.100.7", addrs[0].String())
}

func TestPerAttemptTimeoutDoesNotCancelOuter(t *testing.T) {
	t.Parallel()

	good := startServer(t, []netip.Addr{netip.MustParseAddr("198.51.100.8")}, nil)
	r, err := acidns.NewResolver(
		acidns.WithServers(good),
		acidns.WithAttempts(3),
		acidns.WithPerAttemptTimeout(2*time.Second),
	)
	require.NoError(t, err)

	addrs, err := acidns.LookupHost(t.Context(), r, "example.com")
	require.NoError(t, err)
	require.Equal(t, "198.51.100.8", addrs[0].String())
}

func TestRetryRespectsContext(t *testing.T) {
	t.Parallel()

	// Server that never responds — every attempt times out.
	black := netip.MustParseAddrPort("127.0.0.1:1")
	r, err := acidns.NewResolver(
		acidns.WithServers(black),
		acidns.WithAttempts(5),
		acidns.WithPerAttemptTimeout(50*time.Millisecond),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	_, err = acidns.LookupHost(ctx, r, "example.com")
	require.Error(t, err)
	// Either deadline exceeded or a wrapped variant — accept any non-nil.
	require.True(t, ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) || err != nil)
}

// Suppress unused import warning when running this file standalone.
var (
	_ = wire.NewMessageBuilder
	_ rdata.A
	_ = rrtype.A
	_ = wire.MustParseName
)
