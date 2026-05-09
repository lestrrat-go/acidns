package forward_test

import (
	"context"
	"errors"
	"testing"

	"github.com/lestrrat-go/acidns/forward"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/wiretest"
	"github.com/stretchr/testify/require"
)

// closableUpstream is an Exchanger that records whether Close was called.
type closableUpstream struct {
	closed   bool
	closeErr error
}

func (u *closableUpstream) Exchange(_ context.Context, q wire.Message) (wire.Message, error) {
	return wiretest.Response(q), nil
}

func (u *closableUpstream) Close() error {
	u.closed = true
	return u.closeErr
}

// plainUpstream is an Exchanger without Close.
type plainUpstream struct{}

func (plainUpstream) Exchange(_ context.Context, q wire.Message) (wire.Message, error) {
	return wiretest.Response(q), nil
}

func TestHandler_Close_PropagatesToUpstream(t *testing.T) {
	t.Parallel()
	up := &closableUpstream{}
	h, err := forward.New(forward.WithUpstream(up))
	require.NoError(t, err)

	require.NoError(t, h.Close())
	require.True(t, up.closed)
}

func TestHandler_Close_PropagatesError(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("upstream gone")
	up := &closableUpstream{closeErr: wantErr}
	h, err := forward.New(forward.WithUpstream(up))
	require.NoError(t, err)

	require.ErrorIs(t, h.Close(), wantErr)
}

func TestHandler_Close_NopUpstream(t *testing.T) {
	t.Parallel()
	h, err := forward.New(forward.WithUpstream(plainUpstream{}))
	require.NoError(t, err)

	require.NoError(t, h.Close())
}
