package acidns_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/stretchr/testify/require"
)

func TestSystemResolversAppliesTimeoutAndAttempts(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "resolv.conf")
	body := "nameserver 198.51.100.1\noptions timeout:3 attempts:5\n"
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))

	perAttempt, attempts, err := acidns.SystemResolverConfigFromFile(p)
	require.NoError(t, err)
	require.Equal(t, 3*time.Second, perAttempt)
	require.Equal(t, 5, attempts)
}

func TestSystemResolversClampsExtremeValues(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "resolv.conf")
	body := "nameserver 198.51.100.1\noptions timeout:600 attempts:100\n"
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))

	perAttempt, attempts, err := acidns.SystemResolverConfigFromFile(p)
	require.NoError(t, err)
	require.Equal(t, 30*time.Second, perAttempt)
	require.Equal(t, 10, attempts)
}
