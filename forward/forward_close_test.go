package forward_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/forward"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/internal/wiretest"
	"github.com/stretchr/testify/require"
)

// closableUpstream is an Exchanger that records whether Close was called.
type closableUpstream struct {
	closed atomic.Bool
}

func (u *closableUpstream) Exchange(_ context.Context, q wire.Message) (wire.Message, error) {
	return wiretest.Response(q)
}

func (u *closableUpstream) Close() error {
	u.closed.Store(true)
	return nil
}

// plainUpstream is an Exchanger without Close.
type plainUpstream struct{}

func (plainUpstream) Exchange(_ context.Context, q wire.Message) (wire.Message, error) {
	return wiretest.Response(q)
}

// TestForwarder_CtxCancel_ClosesUpstream verifies that cancelling the
// lifecycle ctx supplied via [forward.WithContext] propagates a
// Close call to the upstream when the upstream implements
// [io.Closer].
func TestForwarder_CtxCancel_ClosesUpstream(t *testing.T) {
	t.Parallel()
	up := &closableUpstream{}
	ctx, cancel := context.WithCancel(t.Context())
	_, err := forward.New(up, forward.WithContext(ctx))
	require.NoError(t, err)

	cancel()
	require.Eventually(t, up.closed.Load, time.Second, 5*time.Millisecond,
		"upstream Close must run when lifecycle ctx is cancelled")
}

// TestForwarder_CtxCancel_NopUpstream verifies that a non-Closer
// upstream is left untouched on ctx cancel (no panic).
func TestForwarder_CtxCancel_NopUpstream(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	_, err := forward.New(plainUpstream{}, forward.WithContext(ctx))
	require.NoError(t, err)
	cancel()
	// No assertion beyond "did not panic"; give the lifecycle
	// goroutine a moment to run cleanup.
	time.Sleep(20 * time.Millisecond)
}
