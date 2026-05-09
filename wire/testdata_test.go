package wire_test

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// expectedFixture lists the expected (qname, qtype, answer-rrtype) tuple
// for each .hex fixture under wire/testdata/. The fixtures are produced
// by ./internal/cmd/genfixtures using the wiretest builders; this table mirrors
// what that generator emits. When adding a new fixture, regenerate via
// `go run ./internal/cmd/genfixtures ./wire/testdata` and add an entry here.
//
// The match is byte-for-byte on qname (canonical wire form is
// lower-cased), and asserts at least one record of the expected rrtype
// in the answer section. The OPT fixture is special-cased: it lives in
// the additional section as the EDNS pseudo-RR and is checked via
// Message.EDNS().
// Repeated qnames hoisted to constants — keeps the goconst linter quiet
// without losing the table-shape readability of the fixture map.
const (
	fxApex     = "example.com."
	fxWWW      = "www.example.com."
	fxRevV4    = "1.0.0.127.in-addr.arpa."
	fxSIP      = "_sip._udp.example.com."
	fxNAPTR    = "naptr.example.com."
	fxTLSA     = "_443._tcp.example.com."
	fxSSHFP    = "ssh.example.com."
	fxSVCBName = "_dns.example.com."
	fxHTTPS    = "svc.example.com."
)

var expectedFixture = map[string]struct {
	qname  string
	qtype  rrtype.Type
	answer rrtype.Type // 0 means: no answer record expected (e.g. opt fixture)
}{
	"a":      {fxApex, rrtype.A, rrtype.A},
	"aaaa":   {fxApex, rrtype.AAAA, rrtype.AAAA},
	"mx":     {fxApex, rrtype.MX, rrtype.MX},
	"txt":    {fxApex, rrtype.TXT, rrtype.TXT},
	"cname":  {fxWWW, rrtype.CNAME, rrtype.CNAME},
	"soa":    {fxApex, rrtype.SOA, rrtype.SOA},
	"ns":     {fxApex, rrtype.NS, rrtype.NS},
	"ptr":    {fxRevV4, rrtype.PTR, rrtype.PTR},
	"srv":    {fxSIP, rrtype.SRV, rrtype.SRV},
	"naptr":  {fxNAPTR, rrtype.NAPTR, rrtype.NAPTR},
	"caa":    {fxApex, rrtype.CAA, rrtype.CAA},
	"tlsa":   {fxTLSA, rrtype.TLSA, rrtype.TLSA},
	"sshfp":  {fxSSHFP, rrtype.SSHFP, rrtype.SSHFP},
	"dnskey": {fxApex, rrtype.DNSKEY, rrtype.DNSKEY},
	"ds":     {fxApex, rrtype.DS, rrtype.DS},
	"rrsig":  {fxApex, rrtype.RRSIG, rrtype.RRSIG},
	"nsec":   {fxApex, rrtype.NSEC, rrtype.NSEC},
	"nsec3":  {fxApex, rrtype.NSEC3, rrtype.NSEC3},
	"opt":    {fxApex, rrtype.A, 0}, // OPT lives in the EDNS pseudo-RR
	"svcb":   {fxSVCBName, rrtype.SVCB, rrtype.SVCB},
	"https":  {fxHTTPS, rrtype.HTTPS, rrtype.HTTPS},
}

// TestTestdataRoundtrip walks every wire/testdata/*.hex fixture, decodes
// it via [wire.Unmarshal], re-marshals it (must not error), and asserts
// the basic invariant from expectedFixture. We deliberately do NOT
// assert byte-for-byte equality because name compression is non-canonical
// and the encoder may legitimately produce a different (still-valid)
// encoding than the input.
func TestTestdataRoundtrip(t *testing.T) {
	matches, err := filepath.Glob("testdata/*.hex")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("no fixtures found under wire/testdata/*.hex")
	}
	seen := make(map[string]bool, len(matches))
	for _, path := range matches {
		base := strings.TrimSuffix(filepath.Base(path), ".hex")
		seen[base] = true
		t.Run(base, func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			buf, err := hex.DecodeString(strings.TrimSpace(string(raw)))
			if err != nil {
				t.Fatalf("decode hex: %v", err)
			}
			m, err := wire.Unmarshal(buf)
			if err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if _, err := wire.Marshal(m); err != nil {
				t.Fatalf("re-Marshal of decoded fixture failed: %v", err)
			}
			exp, ok := expectedFixture[base]
			if !ok {
				t.Fatalf("no expectedFixture entry for %s", base)
			}
			qs := m.Questions()
			if len(qs) != 1 {
				t.Fatalf("want 1 question, got %d", len(qs))
			}
			if got := qs[0].Name().String(); got != exp.qname {
				t.Errorf("qname: want %q, got %q", exp.qname, got)
			}
			if got := qs[0].Type(); got != exp.qtype {
				t.Errorf("qtype: want %v, got %v", exp.qtype, got)
			}
			if exp.answer == 0 {
				// OPT fixture — no answer; verify EDNS surfaced instead.
				if _, ok := m.EDNS(); !ok {
					t.Error("expected EDNS on opt fixture, none found")
				}
				return
			}
			var found bool
			for _, rec := range m.Answers() {
				if rec.Type() == exp.answer {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("no %v record in answer section", exp.answer)
			}
		})
	}
	for name := range expectedFixture {
		if !seen[name] {
			t.Errorf("expectedFixture has %q but no testdata/%s.hex on disk", name, name)
		}
	}
}
