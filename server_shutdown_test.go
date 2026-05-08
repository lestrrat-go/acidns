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
// the same UDPServer config holder spawns independent instances. The
// config is immutable; each Run binds a fresh socket and returns its
// own Controller, so a UDPServer can fan out to N parallel listeners
// (different ports via the kernel's port=0 ephemeral assignment).
func TestUDPServer_RunSpawnsIndependentInstances(t *testing.T) {
	t.Parallel()
	srv, err := acidns.NewUDPServer(netip.MustParseAddrPort("127.0.0.1:0"), echoHandler{})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	c1, err := srv.Run(ctx)
	require.NoError(t, err)
	c2, err := srv.Run(ctx)
	require.NoError(t, err)
	require.NotEqual(t, c1.Addr(), c2.Addr(),
		"each Run should bind a distinct ephemeral port")
}

// TestController_Wait verifies that Wait blocks until the work
// goroutine exits and returns Err()'s value, replacing the longer
// `<-Done(); Err()` idiom for the common "wait then check" path.
func TestController_Wait(t *testing.T) {
	t.Parallel()

	t.Run("udp clean shutdown", func(t *testing.T) {
		t.Parallel()
		srv, err := acidns.NewUDPServer(netip.MustParseAddrPort("127.0.0.1:0"), echoHandler{})
		require.NoError(t, err)
		ctx, cancel := context.WithCancel(t.Context())
		ctrl, err := srv.Run(ctx)
		require.NoError(t, err)

		// Wait must block until the loop exits.
		done := make(chan error, 1)
		go func() { done <- ctrl.Wait() }()
		select {
		case <-done:
			t.Fatal("Wait returned before ctx cancellation")
		case <-time.After(50 * time.Millisecond):
		}

		cancel()
		select {
		case waitErr := <-done:
			require.NoError(t, waitErr, "clean shutdown via ctx cancel must yield nil from Wait")
		case <-time.After(2 * time.Second):
			t.Fatal("Wait did not return after ctx cancel")
		}
	})

	t.Run("tcp clean shutdown", func(t *testing.T) {
		t.Parallel()
		srv, err := acidns.NewTCPServer(netip.MustParseAddrPort("127.0.0.1:0"), echoHandler{})
		require.NoError(t, err)
		ctx, cancel := context.WithCancel(t.Context())
		ctrl, err := srv.Run(ctx)
		require.NoError(t, err)
		cancel()
		require.NoError(t, ctrl.Wait())
	})

	t.Run("wait after exit returns immediately", func(t *testing.T) {
		t.Parallel()
		srv, err := acidns.NewUDPServer(netip.MustParseAddrPort("127.0.0.1:0"), echoHandler{})
		require.NoError(t, err)
		ctx, cancel := context.WithCancel(t.Context())
		ctrl, err := srv.Run(ctx)
		require.NoError(t, err)
		cancel()
		require.NoError(t, ctrl.Wait())
		// Second call sees the closed channel immediately.
		require.NoError(t, ctrl.Wait())
	})
}
