package zonefile_test

import (
	"strings"
	"testing"

	"github.com/lestrrat-go/acidns/zonefile"
)

// FuzzParse feeds zonefile.Parse arbitrary master-file text. The contract:
// must not panic and must surface every parse failure as a wrapped
// ErrParse (we only check non-panic; the error wrapping is covered by
// regular tests).
func FuzzParse(f *testing.F) {
	f.Add("$ORIGIN example.com.\n@ IN SOA ns admin 1 3600 600 86400 3600\n")
	f.Add("$TTL 60\nfoo IN A 192.0.2.1\nbar IN AAAA 2001:db8::1\n")
	f.Add("")
	f.Add(";just a comment\n")
	f.Add("@ IN NS")            // truncated record
	f.Add("foo IN TXT \"unter") // unterminated quote

	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = zonefile.Parse(strings.NewReader(s))
	})
}
