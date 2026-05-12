package zonefile

import (
	"fmt"
	"io"
	"io/fs"
	pathpkg "path"
	"strings"

	"github.com/lestrrat-go/acidns/wire"
)

// DefaultIncludeMaxDepth caps how deeply $INCLUDE may nest. Tunable
// via [WithIncludeMaxDepth]. Generous for legitimate operational
// hierarchies; low enough that a malicious include loop fails fast
// rather than blowing the stack.
const DefaultIncludeMaxDepth = 8

// IncludeResolver opens the file named by a $INCLUDE directive.
// Implementations MUST treat name as untrusted input and contain
// any filesystem access to a sandbox of their choosing — the parser
// performs no path validation itself.
//
// includer is the canonical name of the file containing the
// $INCLUDE directive (or "" for the top-level source). name is the
// argument to $INCLUDE verbatim. The returned canonical string is
// stored both for error messages and as the includer argument for
// nested includes resolved from the opened file.
type IncludeResolver interface {
	ResolveInclude(includer, name string) (io.ReadCloser, string, error)
}

// IncludeResolverFunc adapts a function to [IncludeResolver],
// mirroring the [net/http.HandlerFunc] pattern.
type IncludeResolverFunc func(includer, name string) (io.ReadCloser, string, error)

// ResolveInclude calls f(includer, name).
func (f IncludeResolverFunc) ResolveInclude(includer, name string) (io.ReadCloser, string, error) {
	return f(includer, name)
}

// NewFSIncludeResolver returns an [IncludeResolver] that opens files
// from fsys. Paths are resolved relative to the directory of the
// including file (BIND convention); the [io/fs.FS] interface naturally
// sandboxes the lookup so neither absolute paths nor `..` segments
// can escape the root.
//
// A typical wiring:
//
//	fsys := os.DirFS("/etc/dns/zones")
//	f, _ := fsys.Open("example.com.zone")
//	defer f.Close()
//	zone, err := zonefile.Parse(f,
//	    zonefile.WithIncludeResolver(zonefile.NewFSIncludeResolver(fsys)),
//	    zonefile.WithSourceName("example.com.zone"),
//	)
//
// The WithSourceName option tells the resolver the directory of the
// top-level file so first-level $INCLUDEs resolve relative to it.
func NewFSIncludeResolver(fsys fs.FS) IncludeResolver {
	return &fsIncludeResolver{fsys: fsys}
}

type fsIncludeResolver struct {
	fsys fs.FS
}

func (r *fsIncludeResolver) ResolveInclude(includer, name string) (io.ReadCloser, string, error) {
	// Reject before joining: path.Join would silently resolve `..` away,
	// allowing an attacker-controlled name like "../escape.zone" to
	// reach a sibling-of-includer file. Strict default per the package
	// godoc: a $INCLUDE name must be a relative path with no traversal
	// segments and no absolute prefix.
	if !fs.ValidPath(name) {
		return nil, "", fmt.Errorf("invalid include path %q", name)
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == ".." {
			return nil, "", fmt.Errorf("invalid include path %q: .. segment not allowed", name)
		}
	}
	resolved := name
	if includer != "" {
		if dir := pathpkg.Dir(includer); dir != "." {
			resolved = pathpkg.Join(dir, name)
		}
	}
	if !fs.ValidPath(resolved) {
		return nil, "", fmt.Errorf("invalid include path %q", resolved)
	}
	f, err := r.fsys.Open(resolved)
	if err != nil {
		return nil, "", fmt.Errorf("open include %q: %w", resolved, err)
	}
	return f, resolved, nil
}

// handleInclude executes one $INCLUDE directive.
//
// Grammar (RFC 1035 §5.1, BIND-compatible):
//
//	$INCLUDE <file-name> [<domain-name>]
//
// Scoping (acidns choice, documented in package godoc):
//   - $ORIGIN inside the included file does NOT propagate back.
//   - $TTL inside the included file does NOT propagate back.
//   - The optional <domain-name> sets $ORIGIN for the included file
//     only; the parent's $ORIGIN survives intact.
func (p *parser) handleInclude(fields []fieldTok) error {
	line := fields[0].line
	if p.includeResolver == nil {
		return p.lineErr(line, "$INCLUDE not enabled (supply WithIncludeResolver)")
	}
	if len(fields) < 2 || len(fields) > 3 {
		return p.lineErr(line, "$INCLUDE expects <file-name> [<domain-name>], got %d args", len(fields)-1)
	}
	if p.includeDepth >= p.maxIncludeDepth {
		return p.lineErr(line, "$INCLUDE depth %d exceeds cap (use WithIncludeMaxDepth)", p.maxIncludeDepth)
	}

	includeOrigin := p.origin
	if len(fields) == 3 {
		n, err := wire.ParseName(fields[2].text)
		if err != nil {
			return p.lineErr(line, "$INCLUDE <domain-name>: %w", err)
		}
		includeOrigin = n
	}

	rc, canonical, err := p.includeResolver.ResolveInclude(p.source, fields[1].text)
	if err != nil {
		return p.lineErr(line, "$INCLUDE %q: %w", fields[1].text, err)
	}
	defer rc.Close()

	nested := newParser(rc, config{
		origin:                includeOrigin,
		defaultTTL:            p.defaultTTL,
		maxGenerateIterations: p.maxGenerateIterations,
	})
	nested.source = canonical
	nested.includeDepth = p.includeDepth + 1
	nested.maxIncludeDepth = p.maxIncludeDepth
	nested.includeResolver = p.includeResolver

	if err := nested.run(); err != nil {
		return fmt.Errorf("%w (included from %s)", err, p.includeLocation(line))
	}
	// Scoping: nested $ORIGIN / $TTL do NOT leak back; we drop
	// nested.origin and nested.defaultTTL on the floor.
	p.records = append(p.records, nested.records...)
	return nil
}

// includeLocation renders the source:line label used for "(included
// from ...)" suffixes. Mirrors [parser.lineErr]'s top-level vs sourced
// shape so the chain reads consistently.
func (p *parser) includeLocation(line int) string {
	if p.source != "" {
		return fmt.Sprintf("%s:%d", p.source, line)
	}
	return fmt.Sprintf("line %d", line)
}
