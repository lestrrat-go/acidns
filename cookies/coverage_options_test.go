package cookies_test

import (
	"log/slog"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/cookies"
	"github.com/stretchr/testify/require"
)

// TestLoggerAndSkewOptionsAccepted covers the three previously-uncalled
// options: client/pool loggers (silenced by default; this asserts they
// can be wired up) and the server's WithClockSkew override.
func TestLoggerAndSkewOptionsAccepted(t *testing.T) {
	t.Parallel()
	silent := slog.New(slog.DiscardHandler)

	_, err := cookies.NewClient(cookies.WithClientLogger(silent))
	require.NoError(t, err)

	pool, err := cookies.NewSecretPool(cookies.WithPoolLogger(silent))
	require.NoError(t, err)
	require.NotNil(t, pool)

	srv, err := cookies.NewServer(pool, cookies.WithClockSkew(45*time.Second))
	require.NoError(t, err)
	require.NotNil(t, srv)
}
