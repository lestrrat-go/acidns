package acidns_test

import (
	"context"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/doh"
	"github.com/lestrrat-go/acidns/dot"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// TestE2ELiveResolver hits a real public resolver. Skipped unless
// ACIDNS_E2E=1 is set, so CI without network access can stay green.
func TestE2ELiveResolver(t *testing.T) {
	if os.Getenv("ACIDNS_E2E") == "" {
		t.Skip("set ACIDNS_E2E=1 to enable")
	}

	addr := netip.MustParseAddrPort("1.1.1.1:53")
	r, err := acidns.NewResolver(acidns.WithServers(addr))
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	t.Run("UDP LookupHost example.com", func(t *testing.T) {
		addrs, err := acidns.LookupHost(ctx, r, "example.com")
		require.NoError(t, err)
		require.NotEmpty(t, addrs)
		t.Logf("example.com -> %v", addrs)
	})

	t.Run("UDP Resolve MX cloudflare.com", func(t *testing.T) {
		ans, err := r.Resolve(ctx, wire.MustParseName("cloudflare.com"), rrtype.MX)
		require.NoError(t, err)
		require.NotEmpty(t, ans.Records())
		t.Logf("MX cloudflare.com -> %d records", len(ans.Records()))
	})

	t.Run("DoT via 1.1.1.1:853", func(t *testing.T) {
		ex, err := dot.New(netip.MustParseAddrPort("1.1.1.1:853"),
			dot.WithServerName("cloudflare-dns.com"))
		require.NoError(t, err)
		rd, err := acidns.NewResolver(acidns.WithExchanger(ex))
		require.NoError(t, err)
		addrs, err := acidns.LookupHost(ctx, rd, "example.com")
		require.NoError(t, err)
		require.NotEmpty(t, addrs)
		t.Logf("DoT example.com -> %v", addrs)
	})

	t.Run("DoH via cloudflare-dns.com", func(t *testing.T) {
		ex, err := doh.New("https://cloudflare-dns.com/dns-query")
		require.NoError(t, err)
		rh, err := acidns.NewResolver(acidns.WithExchanger(ex))
		require.NoError(t, err)
		addrs, err := acidns.LookupHost(ctx, rh, "example.com")
		require.NoError(t, err)
		require.NotEmpty(t, addrs)
		t.Logf("DoH example.com -> %v", addrs)
	})
}
