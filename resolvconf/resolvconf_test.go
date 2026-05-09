package resolvconf_test

import (
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/resolvconf"
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
	}, cfg.Nameservers())

	require.Equal(t, 2, len(cfg.Search()))
	require.Equal(t, "example.com.", cfg.Search()[0].String())
	require.Equal(t, 3, cfg.Ndots())
	require.Equal(t, 7*time.Second, cfg.Timeout())
	require.Equal(t, 4, cfg.Attempts())
	require.Contains(t, cfg.Verbatim(), "options use-vc")
}

func TestParseDefaults(t *testing.T) {
	t.Parallel()
	cfg, err := resolvconf.Parse(strings.NewReader("nameserver 9.9.9.9\n"))
	require.NoError(t, err)
	require.Equal(t, 1, cfg.Ndots())
	require.Equal(t, 5*time.Second, cfg.Timeout())
	require.Equal(t, 2, cfg.Attempts())
}

// TestParseSkipsMalformedAndPreservesUnknown exercises the branches that drop
// invalid nameserver/search entries and route unknown top-level directives into
// Verbatim.
func TestParseSkipsMalformedAndPreservesUnknown(t *testing.T) {
	t.Parallel()
	// A label longer than 63 octets is not a legal DNS label and ParseName
	// must reject it; this exercises the search-skip branch.
	tooLong := strings.Repeat("a", 64)
	in := "nameserver\n" +
		"nameserver not-an-address\n" +
		"search valid.example.com " + tooLong + ".example.com\n" +
		"sortlist 10.0.0.0/8\n"
	cfg, err := resolvconf.Parse(strings.NewReader(in))
	require.NoError(t, err)
	require.Empty(t, cfg.Nameservers(), "bare nameserver and invalid address must be skipped")
	require.Len(t, cfg.Search(), 1, "only the valid search entry should survive")
	require.Equal(t, "valid.example.com.", cfg.Search()[0].String())
	require.Contains(t, cfg.Verbatim(), "sortlist 10.0.0.0/8", "unknown directive must be preserved verbatim")
}

// TestParseDomainInvalid covers the domain directive when the name is invalid:
// the field must be silently ignored and Search left untouched.
func TestParseDomainInvalid(t *testing.T) {
	t.Parallel()
	tooLong := strings.Repeat("a", 64) + ".example.com"
	cfg, err := resolvconf.Parse(strings.NewReader("domain " + tooLong + "\n"))
	require.NoError(t, err)
	require.Empty(t, cfg.Search())
}

// errReader returns a fixed error from Read, exercising the bufio.Scanner
// error path inside Parse.
type errReader struct{ err error }

func (r *errReader) Read([]byte) (int, error) { return 0, r.err }

func TestParseScannerError(t *testing.T) {
	t.Parallel()
	want := errors.New("boom")
	_, err := resolvconf.Parse(&errReader{err: want})
	require.Error(t, err)
	require.ErrorIs(t, err, want)
}

// Sanity: ensure io.EOF (the well-behaved end signal) is not reported as an
// error, distinguishing it from the scanner error case above.
func TestParseEOFIsNotError(t *testing.T) {
	t.Parallel()
	cfg, err := resolvconf.Parse(&errReader{err: io.EOF})
	require.NoError(t, err)
	require.NotNil(t, cfg)
}
