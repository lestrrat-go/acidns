package zonefile_test

import (
	"io"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/zonefile"
	"github.com/stretchr/testify/require"
)

// makeFS builds a testing/fstest.MapFS from name→content pairs.
func makeFS(t *testing.T, files map[string]string) fs.FS {
	t.Helper()
	m := fstest.MapFS{}
	for name, content := range files {
		m[name] = &fstest.MapFile{Data: []byte(content)}
	}
	return m
}

// readFromFS opens name in fsys for handing to Parse as the top-level
// io.Reader.
func readFromFS(t *testing.T, fsys fs.FS, name string) io.Reader {
	t.Helper()
	f, err := fsys.Open(name)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func TestIncludeBasic(t *testing.T) {
	t.Parallel()
	fsys := makeFS(t, map[string]string{
		"main.zone": `$ORIGIN example.com.
$TTL 60
@   IN  SOA  ns1.example.com. hm.example.com. ( 1 2 3 4 5 )
www IN  A    192.0.2.42
$INCLUDE "sub.zone"
mail IN A    192.0.2.99
`,
		"sub.zone": `host1 IN A 192.0.2.10
host2 IN A 192.0.2.11
`,
	})
	z, err := zonefile.Parse(readFromFS(t, fsys, "main.zone"),
		zonefile.WithIncludeResolver(zonefile.NewFSIncludeResolver(fsys)),
		zonefile.WithSourceName("main.zone"),
	)
	require.NoError(t, err)
	recs := z.Records()
	require.Equal(t, 5, len(recs)) // SOA + www + host1 + host2 + mail

	owners := make([]string, len(recs))
	for i, r := range recs {
		owners[i] = r.Name().String()
	}
	require.Equal(t, []string{
		"example.com.",
		"www.example.com.",
		"host1.example.com.",
		"host2.example.com.",
		"mail.example.com.",
	}, owners)
}

func TestIncludeRejectsWithoutResolver(t *testing.T) {
	t.Parallel()
	src := `$ORIGIN example.com.
$TTL 60
$INCLUDE "sub.zone"
`
	_, err := zonefile.Parse(strings.NewReader(src))
	require.Error(t, err)
	require.Contains(t, err.Error(), "$INCLUDE not enabled")
}

func TestIncludeLocalOriginScoping(t *testing.T) {
	t.Parallel()
	// Sub-file sets its own $ORIGIN; the parent's $ORIGIN must survive.
	fsys := makeFS(t, map[string]string{
		"main.zone": `$ORIGIN example.com.
$TTL 60
@   IN  SOA  ns1.example.com. hm.example.com. ( 1 2 3 4 5 )
$INCLUDE "sub.zone"
after IN A 192.0.2.99
`,
		"sub.zone": `$ORIGIN child.example.com.
inside IN A 192.0.2.10
`,
	})
	z, err := zonefile.Parse(readFromFS(t, fsys, "main.zone"),
		zonefile.WithIncludeResolver(zonefile.NewFSIncludeResolver(fsys)),
		zonefile.WithSourceName("main.zone"),
	)
	require.NoError(t, err)
	owners := make([]string, len(z.Records()))
	for i, r := range z.Records() {
		owners[i] = r.Name().String()
	}
	require.Equal(t, []string{
		"example.com.",              // SOA
		"inside.child.example.com.", // inside the include, child origin
		"after.example.com.",        // parent origin restored
	}, owners)
}

func TestIncludeExplicitDomainArgument(t *testing.T) {
	t.Parallel()
	// $INCLUDE "sub.zone" sub.example.com. — origin override for the include.
	fsys := makeFS(t, map[string]string{
		"main.zone": `$ORIGIN example.com.
$TTL 60
@   IN  SOA  ns1.example.com. hm.example.com. ( 1 2 3 4 5 )
$INCLUDE "sub.zone" sub.example.com.
after IN A 192.0.2.99
`,
		"sub.zone": `inside IN A 192.0.2.10
`,
	})
	z, err := zonefile.Parse(readFromFS(t, fsys, "main.zone"),
		zonefile.WithIncludeResolver(zonefile.NewFSIncludeResolver(fsys)),
		zonefile.WithSourceName("main.zone"),
	)
	require.NoError(t, err)
	recs := z.Records()
	var insideOwner, afterOwner string
	for _, r := range recs {
		if a, ok := wire.RDataAs[rdata.A](r); ok {
			if a.Addr().String() == "192.0.2.10" {
				insideOwner = r.Name().String()
			}
			if a.Addr().String() == "192.0.2.99" {
				afterOwner = r.Name().String()
			}
		}
	}
	require.Equal(t, "inside.sub.example.com.", insideOwner)
	require.Equal(t, "after.example.com.", afterOwner)
}

func TestIncludeLocalTTLScoping(t *testing.T) {
	t.Parallel()
	// Sub sets $TTL 999; parent's $TTL 60 must apply after the include.
	fsys := makeFS(t, map[string]string{
		"main.zone": `$ORIGIN example.com.
$TTL 60
@   IN  SOA  ns1.example.com. hm.example.com. ( 1 2 3 4 5 )
$INCLUDE "sub.zone"
after IN A 192.0.2.99
`,
		"sub.zone": `$TTL 999
inside IN A 192.0.2.10
`,
	})
	z, err := zonefile.Parse(readFromFS(t, fsys, "main.zone"),
		zonefile.WithIncludeResolver(zonefile.NewFSIncludeResolver(fsys)),
		zonefile.WithSourceName("main.zone"),
	)
	require.NoError(t, err)
	var insideTTL, afterTTL int
	for _, r := range z.Records() {
		if a, ok := wire.RDataAs[rdata.A](r); ok {
			if a.Addr().String() == "192.0.2.10" {
				insideTTL = int(r.TTL().Seconds())
			}
			if a.Addr().String() == "192.0.2.99" {
				afterTTL = int(r.TTL().Seconds())
			}
		}
	}
	require.Equal(t, 999, insideTTL)
	require.Equal(t, 60, afterTTL)
}

func TestIncludeNestedRelativeResolution(t *testing.T) {
	t.Parallel()
	// main.zone (root) → sub/a.zone → sub/b.zone (sibling).
	fsys := makeFS(t, map[string]string{
		"main.zone": `$ORIGIN example.com.
$TTL 60
@   IN  SOA  ns1.example.com. hm.example.com. ( 1 2 3 4 5 )
$INCLUDE "sub/a.zone"
`,
		"sub/a.zone": `host-a IN A 192.0.2.10
$INCLUDE "b.zone"
`,
		"sub/b.zone": `host-b IN A 192.0.2.11
`,
	})
	z, err := zonefile.Parse(readFromFS(t, fsys, "main.zone"),
		zonefile.WithIncludeResolver(zonefile.NewFSIncludeResolver(fsys)),
		zonefile.WithSourceName("main.zone"),
	)
	require.NoError(t, err)
	owners := make([]string, 0)
	for _, r := range z.Records() {
		if _, ok := wire.RDataAs[rdata.A](r); ok {
			owners = append(owners, r.Name().String())
		}
	}
	require.Equal(t, []string{"host-a.example.com.", "host-b.example.com."}, owners)
}

func TestIncludeDepthCap(t *testing.T) {
	t.Parallel()
	// Cycle: a.zone includes b.zone which includes a.zone.
	fsys := makeFS(t, map[string]string{
		"a.zone": `$INCLUDE "b.zone"`,
		"b.zone": `$INCLUDE "a.zone"`,
	})
	_, err := zonefile.Parse(readFromFS(t, fsys, "a.zone"),
		zonefile.WithIncludeResolver(zonefile.NewFSIncludeResolver(fsys)),
		zonefile.WithSourceName("a.zone"),
		zonefile.WithIncludeMaxDepth(3),
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds cap")
}

func TestIncludeFSResolverRejectsEscape(t *testing.T) {
	t.Parallel()
	// `..` is rejected by fs.ValidPath used inside fsIncludeResolver.
	fsys := makeFS(t, map[string]string{
		"zones/main.zone": `$INCLUDE "../escape.zone"`,
		"escape.zone":     `; should never be parsed`,
	})
	_, err := zonefile.Parse(readFromFS(t, fsys, "zones/main.zone"),
		zonefile.WithIncludeResolver(zonefile.NewFSIncludeResolver(fsys)),
		zonefile.WithSourceName("zones/main.zone"),
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid include path")
}

func TestIncludeErrorContextStackTrace(t *testing.T) {
	t.Parallel()
	// sub.zone contains an error on line 2. The error message should
	// label the sub file and chain back to the include site in main.
	fsys := makeFS(t, map[string]string{
		"main.zone": `$ORIGIN example.com.
$TTL 60
$INCLUDE "sub.zone"
`,
		"sub.zone": `host IN A 192.0.2.10
host IN BOGUS xyz
`,
	})
	_, err := zonefile.Parse(readFromFS(t, fsys, "main.zone"),
		zonefile.WithIncludeResolver(zonefile.NewFSIncludeResolver(fsys)),
		zonefile.WithSourceName("main.zone"),
	)
	require.Error(t, err)
	msg := err.Error()
	require.Contains(t, msg, "sub.zone:2")
	require.Contains(t, msg, "BOGUS")
	require.Contains(t, msg, "included from main.zone:3")
}

func TestIncludeResolverFuncAdapter(t *testing.T) {
	t.Parallel()
	// User-supplied resolver via the function adapter; opens hard-coded
	// content rather than touching a filesystem.
	resolver := zonefile.IncludeResolverFunc(func(_, name string) (io.ReadCloser, string, error) {
		if name != "memory.zone" {
			return nil, "", io.EOF
		}
		return io.NopCloser(strings.NewReader("host IN A 192.0.2.5\n")), "memory.zone", nil
	})
	src := `$ORIGIN example.com.
$TTL 60
$INCLUDE "memory.zone"
`
	z, err := zonefile.Parse(strings.NewReader(src),
		zonefile.WithIncludeResolver(resolver),
	)
	require.NoError(t, err)
	require.Equal(t, 1, len(z.Records()))
	a, ok := wire.RDataAs[rdata.A](z.Records()[0])
	require.True(t, ok)
	require.Equal(t, "192.0.2.5", a.Addr().String())
}

func TestIncludeBadArity(t *testing.T) {
	t.Parallel()
	fsys := makeFS(t, map[string]string{
		"main.zone": `$INCLUDE`,
	})
	_, err := zonefile.Parse(readFromFS(t, fsys, "main.zone"),
		zonefile.WithIncludeResolver(zonefile.NewFSIncludeResolver(fsys)),
		zonefile.WithSourceName("main.zone"),
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "$INCLUDE expects")
}
