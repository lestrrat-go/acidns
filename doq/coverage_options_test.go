//go:build !acidns_no_doq

package doq_test

import (
	"context"
	"crypto/tls"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/doq"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/stretchr/testify/require"
)

// TestClientOptionsAccepted exercises the client-side options whose only
// callers would otherwise be elsewhere in user code: WithInsecure and
// WithMaxResponseBytes. Other client options already have coverage in
// doq_test.go / doq_extra_test.go.
func TestClientOptionsAccepted(t *testing.T) {
	t.Parallel()
	addr := netip.MustParseAddrPort("127.0.0.1:65000")
	ex, err := doq.NewClient(addr,
		doq.WithServerName("127.0.0.1"),
		doq.WithInsecure(true),
		doq.WithMaxResponseBytes(8192),
	)
	require.NoError(t, err)
	require.NotNil(t, ex)
}

// TestKeepAliveOptionsAccepted exercises the keep-alive client options
// that have no caller in this repo: WithKeepAliveTimeout / MaxIdleTimeout /
// Padding / MaxResponseBytes. The remaining keep-alive options
// (TLSConfig / ServerName / Insecure / SPKIPin) already have coverage.
func TestKeepAliveOptionsAccepted(t *testing.T) {
	t.Parallel()
	addr := netip.MustParseAddrPort("127.0.0.1:65000")
	c, err := doq.NewKeepAliveClient(addr,
		doq.WithKeepAliveServerName("127.0.0.1"),
		doq.WithKeepAliveInsecure(true),
		doq.WithKeepAliveTimeout(2*time.Second),
		doq.WithKeepAliveMaxIdleTimeout(45*time.Second),
		doq.WithKeepAlivePadding(false),
		doq.WithKeepAliveMaxResponseBytes(8192),
	)
	require.NoError(t, err)
	require.NotNil(t, c)
	require.NoError(t, c.Close())
}

// TestServerOptionsAccepted exercises every server option that otherwise
// has no caller: HandshakeTimeout / IdleTimeout / StreamReadTimeout /
// WriteTimeout / MaxMessageSize / MaxStreamsPerConn / MaxConnections /
// MaxConnLifetime. The remaining option (WithServerTLSConfig) is required
// and is already covered.
func TestServerOptionsAccepted(t *testing.T) {
	t.Parallel()
	cert, _ := doqTestCerts(t)
	h := acidns.HandlerFunc(func(_ context.Context, _ acidns.ResponseWriter, _ wire.Message) {})
	srv, err := doq.NewServer(netip.MustParseAddrPort("127.0.0.1:0"), h,
		doq.WithServerTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
		doq.WithServerHandshakeTimeout(5*time.Second),
		doq.WithServerIdleTimeout(20*time.Second),
		doq.WithServerStreamReadTimeout(5*time.Second),
		doq.WithServerWriteTimeout(3*time.Second),
		doq.WithServerMaxMessageSize(8192),
		doq.WithServerMaxStreamsPerConn(64),
		doq.WithServerMaxConnections(128),
		doq.WithServerMaxConnLifetime(30*time.Minute),
	)
	require.NoError(t, err)
	require.NotNil(t, srv)
}
