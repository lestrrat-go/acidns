package acidns_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/stretchr/testify/require"
)

// TestUDPServer_CleanShutdownOnCtxCancel verifies that cancelling the
// context passed to Run drains the work goroutine cleanly: Done()
// closes, Err() reports nil. The new lifecycle has no Shutdown method
// — ctx cancellation is the single path.
func TestUDPServer_CleanShutdownOnCtxCancel(t *testing.T) {
	t.Parallel()
	srv, err := acidns.NewUDPServer(netip.MustParseAddrPort("127.0.0.1:0"), echoHandler{})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	ctrl, err := srv.Run(ctx)
	require.NoError(t, err)

	cancel()
	select {
	case <-ctrl.Done():
		require.NoError(t, ctrl.Err(), "clean shutdown via ctx cancel must report nil err")
	case <-time.After(2 * time.Second):
		t.Fatal("UDP server did not exit after ctx cancel")
	}
}

// TestTCPServer_CleanShutdownOnCtxCancel mirrors the UDP variant for TCP.
func TestTCPServer_CleanShutdownOnCtxCancel(t *testing.T) {
	t.Parallel()
	srv, err := acidns.NewTCPServer(netip.MustParseAddrPort("127.0.0.1:0"), echoHandler{})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	ctrl, err := srv.Run(ctx)
	require.NoError(t, err)

	cancel()
	select {
	case <-ctrl.Done():
		require.NoError(t, ctrl.Err())
	case <-time.After(2 * time.Second):
		t.Fatal("TCP server did not exit after ctx cancel")
	}
}

// TestUDPServer_RunTwiceFails verifies that calling Run a second time on
// the same server returns an error — the started flag is one-way.
func TestUDPServer_RunTwiceFails(t *testing.T) {
	t.Parallel()
	srv, err := acidns.NewUDPServer(netip.MustParseAddrPort("127.0.0.1:0"), echoHandler{})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	_, err = srv.Run(ctx)
	require.NoError(t, err)
	_, err = srv.Run(ctx)
	require.Error(t, err)
}
