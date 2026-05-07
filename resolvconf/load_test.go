package resolvconf_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lestrrat-go/acidns/resolvconf"
	"github.com/stretchr/testify/require"
)

func TestLoad(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "resolv.conf")
	require.NoError(t, os.WriteFile(p, []byte("nameserver 1.1.1.1\nsearch example.com\n"), 0644))

	cfg, err := resolvconf.Load(p)
	require.NoError(t, err)
	require.Len(t, cfg.Nameservers, 1)
	require.Equal(t, "1.1.1.1:53", cfg.Nameservers[0].String())
}

func TestLoadMissing(t *testing.T) {
	t.Parallel()
	_, err := resolvconf.Load("/no/such/file/here.conf")
	require.Error(t, err)
}
