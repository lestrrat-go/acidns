package acidns_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/stretchr/testify/require"
)

func TestUDPServer_Shutdown_Idempotent(t *testing.T) {
	t.Parallel()
	srv, err := acidns.ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"), echoHandler{})
	require.NoError(t, err)

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(t.Context()) }()

	require.NoError(t, srv.Shutdown(t.Context()))
	require.NoError(t, srv.Shutdown(t.Context())) // second call is a no-op

	select {
	case err := <-serveErr:
		require.True(t, errors.Is(err, acidns.ErrServerClosed), "expected ErrServerClosed, got %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after Shutdown")
	}
}

func TestTCPServer_Shutdown_Idempotent(t *testing.T) {
	t.Parallel()
	srv, err := acidns.ListenTCP(netip.MustParseAddrPort("127.0.0.1:0"), echoHandler{})
	require.NoError(t, err)

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(t.Context()) }()

	require.NoError(t, srv.Shutdown(t.Context()))
	require.NoError(t, srv.Shutdown(t.Context()))

	select {
	case err := <-serveErr:
		require.True(t, errors.Is(err, acidns.ErrServerClosed), "expected ErrServerClosed, got %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after Shutdown")
	}
}

func TestUDPServer_Shutdown_RespectsCtx(t *testing.T) {
	t.Parallel()
	// We don't have a way to block a handler indefinitely without a real
	// query, so this just exercises the happy ctx path.
	srv, err := acidns.ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"), echoHandler{})
	require.NoError(t, err)
	go func() { _ = srv.Serve(t.Context()) }()

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	require.NoError(t, srv.Shutdown(ctx))
}

