package resolvconf_test

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient/resolvconf"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	t.Parallel()
	in := `# comment
; another comment
domain example.com
search example.com sub.example.com
nameserver 1.1.1.1
nameserver 8.8.8.8:5353
nameserver ::1
options ndots:3 timeout:7 attempts:4 use-vc
`
	cfg, err := resolvconf.Parse(strings.NewReader(in))
	require.NoError(t, err)

	require.Equal(t, []netip.AddrPort{
		netip.MustParseAddrPort("1.1.1.1:53"),
		netip.MustParseAddrPort("8.8.8.8:5353"),
		netip.MustParseAddrPort("[::1]:53"),
	}, cfg.Nameservers)

	require.Equal(t, 2, len(cfg.Search))
	require.Equal(t, "example.com.", cfg.Search[0].String())
	require.Equal(t, 3, cfg.Ndots)
	require.Equal(t, 7*time.Second, cfg.Timeout)
	require.Equal(t, 4, cfg.Attempts)
	require.Contains(t, cfg.Verbatim, "options use-vc")
}

func TestParseDefaults(t *testing.T) {
	t.Parallel()
	cfg, err := resolvconf.Parse(strings.NewReader("nameserver 9.9.9.9\n"))
	require.NoError(t, err)
	require.Equal(t, 1, cfg.Ndots)
	require.Equal(t, 5*time.Second, cfg.Timeout)
	require.Equal(t, 2, cfg.Attempts)
}
