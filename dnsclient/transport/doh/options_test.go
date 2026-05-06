package doh_test

import (
	"net/http"
	"testing"

	"github.com/lestrrat-go/acidns/dnsclient/transport/doh"
	"github.com/stretchr/testify/require"
)

func TestNewWithOptions(t *testing.T) {
	t.Parallel()
	ex, err := doh.New("https://cloudflare-dns.com/dns-query",
		doh.WithHTTPClient(http.DefaultClient),
		doh.WithUserAgent("acidns/test"),
	)
	require.NoError(t, err)
	require.NotNil(t, ex)
}
