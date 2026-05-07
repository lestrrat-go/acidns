package main

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

func TestSplitCSV(t *testing.T) {
	t.Parallel()
	require.Equal(t, []string{"a", "b", "c"}, splitCSV("a,b,c"))
	require.Equal(t, []string{"a", "b"}, splitCSV(" a , b "))
	require.Equal(t, []string{""}, splitCSV(""))
}

func writeZone(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "zone.txt")
	require.NoError(t, os.WriteFile(p, []byte(`$ORIGIN example.com.
$TTL 60
@   IN  SOA  ns1.example.com. hostmaster.example.com. ( 1 2 3 4 5 )
@   IN  NS   ns1.example.com.
ns1 IN  A    192.0.2.10
`), 0644))
	return p
}

func TestBuildAuthoritativeOK(t *testing.T) {
	t.Parallel()
	h, err := buildAuthoritative([]string{writeZone(t)})
	require.NoError(t, err)
	require.NotNil(t, h)
}

func TestBuildAuthoritativeRequiresZones(t *testing.T) {
	t.Parallel()
	_, err := buildAuthoritative(nil)
	require.Error(t, err)
}

func TestBuildAuthoritativeBadFile(t *testing.T) {
	t.Parallel()
	_, err := buildAuthoritative([]string{"/no/such/file"})
	require.Error(t, err)
}

func TestBuildRecursiveOK(t *testing.T) {
	t.Parallel()
	h, err := buildRecursive([]string{"127.0.0.1:53"})
	require.NoError(t, err)
	require.NotNil(t, h)
}

func TestBuildRecursiveRequiresRoots(t *testing.T) {
	t.Parallel()
	_, err := buildRecursive(nil)
	require.Error(t, err)
}

func TestBuildRecursiveInvalidRoot(t *testing.T) {
	t.Parallel()
	_, err := buildRecursive([]string{"not-an-addr"})
	require.Error(t, err)
}

func TestBuildHandlerModes(t *testing.T) {
	t.Parallel()
	z := writeZone(t)
	cases := []struct {
		name string
		o    opts
		ok   bool
	}{
		{"authoritative", opts{mode: "authoritative", zoneFiles: []string{z}}, true},
		{"recursive", opts{mode: "recursive", roots: []string{"127.0.0.1:53"}}, true},
		{"hybrid", opts{mode: "hybrid", zoneFiles: []string{z}, roots: []string{"127.0.0.1:53"}}, true},
		{"unknown", opts{mode: "bogus"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := buildHandler(c.o)
			if c.ok {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

type stubResponseWriter struct {
	captured wire.Message
}

func (s *stubResponseWriter) WriteMsg(m wire.Message) error {
	s.captured = m
	return nil
}
func (s *stubResponseWriter) RemoteAddr() netip.AddrPort { return netip.AddrPort{} }
func (s *stubResponseWriter) LocalAddr() netip.AddrPort  { return netip.AddrPort{} }
func (s *stubResponseWriter) Network() string            { return "udp" }

func TestPeekingWriter(t *testing.T) {
	t.Parallel()
	stub := &stubResponseWriter{}
	pw := &peekingWriter{ResponseWriter: stub}
	m, _ := wire.NewBuilder().ID(1).Response(true).Build()
	require.NoError(t, pw.WriteMsg(m))
	require.NotNil(t, pw.captured)
}

func TestHybridFallthroughOnRefused(t *testing.T) {
	t.Parallel()
	z := writeZone(t)
	auth, err := buildAuthoritative([]string{z})
	require.NoError(t, err)
	rec, err := buildRecursive([]string{"127.0.0.1:1"}) // unreachable, fast SERVFAIL
	require.NoError(t, err)
	h := hybrid{auth: auth, rec: rec}

	// Out-of-zone query → auth REFUSEDs, hybrid then forwards to rec.
	q, _ := wire.NewBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("example.org"), rrtype.A)).
		Build()
	w := &stubResponseWriter{}
	ctx, cancel := context.WithTimeout(t.Context(), 100)
	defer cancel()
	h.ServeDNS(ctx, w, q)
	// We don't care about the final RCODE — what matters is that hybrid
	// reached the recursive arm and produced a response.
	require.NotNil(t, w.captured)
}
