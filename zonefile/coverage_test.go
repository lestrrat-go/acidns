package zonefile_test

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/zonefile"
	"github.com/stretchr/testify/require"
)

const minimalZone = "$ORIGIN example.com.\n$TTL 60\n@ IN A 192.0.2.1\n"

// TestParseLexerEdgeCases drives the lexer through the corner cases —
// trailing comment with no newline at EOF, backslash escapes inside a
// bare word, newline inside a quoted string, and unbalanced ')'.
func TestParseLexerEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("comment at EOF without newline", func(t *testing.T) {
		t.Parallel()
		// Comment immediately before EOF after at least one record on the
		// same logical line — exercises lexer.flushOnEOF via the comment
		// branch (the EOF check inside the comment-skip loop).
		src := "$ORIGIN example.com.\n$TTL 60\n@ IN A 192.0.2.1 ; trailing"
		z, err := zonefile.Parse(strings.NewReader(src))
		require.NoError(t, err)
		require.Len(t, z.Records(), 1)
	})

	t.Run("backslash escape in bare word", func(t *testing.T) {
		t.Parallel()
		// A backslash-escaped dot inside a label exercises the readWord
		// escape branch.
		src := "$ORIGIN example.com.\n$TTL 60\nweird\\.label IN A 192.0.2.5\n"
		_, err := zonefile.Parse(strings.NewReader(src))
		require.NoError(t, err)
	})

	t.Run("dangling backslash at EOF in word", func(t *testing.T) {
		t.Parallel()
		src := "$ORIGIN example.com.\n$TTL 60\n@ IN A foo\\"
		_, err := zonefile.Parse(strings.NewReader(src))
		require.Error(t, err)
		require.Contains(t, err.Error(), "dangling backslash")
	})

	t.Run("newline inside quoted string", func(t *testing.T) {
		t.Parallel()
		src := "$ORIGIN example.com.\n$TTL 60\n@ IN TXT \"line1\nline2\"\n"
		z, err := zonefile.Parse(strings.NewReader(src))
		require.NoError(t, err)
		var found bool
		for _, r := range z.Records() {
			if r.Type() == rrtype.TXT {
				found = true
				require.Contains(t, r.RData().(rdata.TXT).Strings()[0], "\n")
			}
		}
		require.True(t, found)
	})

	t.Run("unterminated quoted string", func(t *testing.T) {
		t.Parallel()
		src := "$ORIGIN example.com.\n$TTL 60\n@ IN TXT \"never closed\n"
		_, err := zonefile.Parse(strings.NewReader(src))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unterminated quoted string")
	})

	t.Run("dangling backslash in quoted string", func(t *testing.T) {
		t.Parallel()
		src := "$ORIGIN example.com.\n$TTL 60\n@ IN TXT \"x\\"
		_, err := zonefile.Parse(strings.NewReader(src))
		require.ErrorIs(t, err, zonefile.ErrParse)
	})

	t.Run("unbalanced close paren", func(t *testing.T) {
		t.Parallel()
		src := "$ORIGIN example.com.\n$TTL 60\n@ IN A 192.0.2.1 )\n"
		_, err := zonefile.Parse(strings.NewReader(src))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unexpected ')'")
	})

	t.Run("blank lines and comment-only lines", func(t *testing.T) {
		t.Parallel()
		src := "\n\n; just a comment\n\n$ORIGIN example.com.\n$TTL 60\n; another\n@ IN A 192.0.2.1\n"
		z, err := zonefile.Parse(strings.NewReader(src))
		require.NoError(t, err)
		require.Len(t, z.Records(), 1)
	})

	t.Run("CRLF line endings", func(t *testing.T) {
		t.Parallel()
		src := "$ORIGIN example.com.\r\n$TTL 60\r\n@ IN A 192.0.2.1\r\n"
		z, err := zonefile.Parse(strings.NewReader(src))
		require.NoError(t, err)
		require.Len(t, z.Records(), 1)
	})
}

// TestParseDirectiveErrors covers every error branch in handleDirective.
func TestParseDirectiveErrors(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		src      string
		contains string
	}{
		"$ORIGIN missing arg": {
			src:      "$ORIGIN\n",
			contains: "$ORIGIN needs one argument",
		},
		"$ORIGIN extra args": {
			src:      "$ORIGIN example.com. extra\n",
			contains: "$ORIGIN needs one argument",
		},
		"$ORIGIN bad name": {
			src:      "$ORIGIN ..bad..\n",
			contains: "$ORIGIN",
		},
		"$TTL missing arg": {
			src:      "$TTL\n",
			contains: "$TTL needs one argument",
		},
		"$TTL bad value": {
			src:      "$TTL notanumber\n",
			contains: "$TTL",
		},
		"unknown directive": {
			src:      "$BOGUS arg\n",
			contains: "unknown directive",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := zonefile.Parse(strings.NewReader(c.src))
			require.Error(t, err)
			require.Contains(t, err.Error(), c.contains)
			require.True(t, errors.Is(err, zonefile.ErrParse))
		})
	}
}

// TestParseDirectiveLowercase verifies $ORIGIN / $TTL are case-insensitive.
func TestParseDirectiveLowercase(t *testing.T) {
	t.Parallel()
	src := "$origin example.com.\n$ttl 90\n@ IN A 192.0.2.1\n"
	z, err := zonefile.Parse(strings.NewReader(src))
	require.NoError(t, err)
	rrs := z.Records()
	require.Len(t, rrs, 1)
	require.Equal(t, 90*time.Second, rrs[0].TTL())
}

// TestParseClassBranches covers every branch of parseClass plus the
// "leading class then TTL" ordering.
func TestParseClassBranches(t *testing.T) {
	t.Parallel()

	t.Run("class then ttl ordering", func(t *testing.T) {
		t.Parallel()
		// CLASS first, then TTL: parser should accept either order
		// before the TYPE.
		src := "$ORIGIN example.com.\n$TTL 60\n@ IN 120 A 192.0.2.1\n"
		z, err := zonefile.Parse(strings.NewReader(src))
		require.NoError(t, err)
		require.Equal(t, 120*time.Second, z.Records()[0].TTL())
	})

	t.Run("ttl then class ordering", func(t *testing.T) {
		t.Parallel()
		src := "$ORIGIN example.com.\n$TTL 60\n@ 120 IN A 192.0.2.1\n"
		z, err := zonefile.Parse(strings.NewReader(src))
		require.NoError(t, err)
		require.Equal(t, 120*time.Second, z.Records()[0].TTL())
	})

	t.Run("CHAOS class", func(t *testing.T) {
		t.Parallel()
		src := "$ORIGIN example.com.\n$TTL 60\n@ CH TXT \"chaos\"\n"
		z, err := zonefile.Parse(strings.NewReader(src))
		require.NoError(t, err)
		require.Equal(t, rrtype.ClassCH, z.Records()[0].Class())
	})

	t.Run("HS class", func(t *testing.T) {
		t.Parallel()
		src := "$ORIGIN example.com.\n$TTL 60\n@ HS TXT \"hesiod\"\n"
		z, err := zonefile.Parse(strings.NewReader(src))
		require.NoError(t, err)
		require.Equal(t, rrtype.ClassHS, z.Records()[0].Class())
	})

	t.Run("ANY class", func(t *testing.T) {
		t.Parallel()
		src := "$ORIGIN example.com.\n$TTL 60\n@ ANY TXT \"x\"\n"
		z, err := zonefile.Parse(strings.NewReader(src))
		require.NoError(t, err)
		require.Equal(t, rrtype.ClassANY, z.Records()[0].Class())
	})

	t.Run("NONE class", func(t *testing.T) {
		t.Parallel()
		src := "$ORIGIN example.com.\n$TTL 60\n@ NONE TXT \"x\"\n"
		z, err := zonefile.Parse(strings.NewReader(src))
		require.NoError(t, err)
		require.Equal(t, rrtype.ClassNONE, z.Records()[0].Class())
	})
}

// TestParseRDataErrors covers each per-RR-type error branch in parseRData.
func TestParseRDataErrors(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"A wrong field count":     "$ORIGIN example.com.\n$TTL 60\n@ IN A 1.2.3.4 5.6.7.8\n",
		"A IPv6 not IPv4":         "$ORIGIN example.com.\n$TTL 60\n@ IN A 2001:db8::1\n",
		"AAAA wrong field count":  "$ORIGIN example.com.\n$TTL 60\n@ IN AAAA ::1 ::2\n",
		"AAAA IPv4 not IPv6":      "$ORIGIN example.com.\n$TTL 60\n@ IN AAAA 192.0.2.1\n",
		"NS wrong field count":    "$ORIGIN example.com.\n$TTL 60\n@ IN NS\n",
		"CNAME wrong field count": "$ORIGIN example.com.\n$TTL 60\n@ IN CNAME\n",
		"CNAME bad name":          "$ORIGIN example.com.\n$TTL 60\n@ IN CNAME ..bad\n",
		"PTR wrong field count":   "$ORIGIN example.com.\n$TTL 60\n@ IN PTR\n",
		"PTR bad name":            "$ORIGIN example.com.\n$TTL 60\n@ IN PTR ..bad\n",
		"MX wrong field count":    "$ORIGIN example.com.\n$TTL 60\n@ IN MX 10\n",
		"MX bad preference":       "$ORIGIN example.com.\n$TTL 60\n@ IN MX notanum mail.example.com.\n",
		"MX bad target":           "$ORIGIN example.com.\n$TTL 60\n@ IN MX 10 ..bad\n",
		"SOA wrong field count":   "$ORIGIN example.com.\n$TTL 60\n@ IN SOA ns. hm. 1 2 3\n",
		"SOA bad serial":          "$ORIGIN example.com.\n$TTL 60\n@ IN SOA ns. hm. notanum 7200 3600 1209600 60\n",
		"SOA bad refresh":         "$ORIGIN example.com.\n$TTL 60\n@ IN SOA ns. hm. 1 bad 3600 1209600 60\n",
		"SOA bad retry":           "$ORIGIN example.com.\n$TTL 60\n@ IN SOA ns. hm. 1 7200 bad 1209600 60\n",
		"SOA bad expire":          "$ORIGIN example.com.\n$TTL 60\n@ IN SOA ns. hm. 1 7200 3600 bad 60\n",
		"SOA bad minimum":         "$ORIGIN example.com.\n$TTL 60\n@ IN SOA ns. hm. 1 7200 3600 1209600 bad\n",
		"SOA bad mname":           "$ORIGIN example.com.\n$TTL 60\n@ IN SOA ..bad hm. 1 7200 3600 1209600 60\n",
		"SOA bad rname":           "$ORIGIN example.com.\n$TTL 60\n@ IN SOA ns. ..bad 1 7200 3600 1209600 60\n",
		"unsupported type SRV":    "$ORIGIN example.com.\n$TTL 60\n@ IN SRV 0 0 80 host.example.com.\n",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := zonefile.Parse(strings.NewReader(src))
			require.Error(t, err, "expected error for %q", name)
			require.True(t, errors.Is(err, zonefile.ErrParse))
		})
	}
}

// TestParseBlankOwnerNoPrev verifies the blank-owner error when no prior
// RR has been seen.
func TestParseBlankOwnerNoPrev(t *testing.T) {
	t.Parallel()
	src := "$ORIGIN example.com.\n$TTL 60\n   IN A 192.0.2.1\n"
	_, err := zonefile.Parse(strings.NewReader(src))
	require.Error(t, err)
	require.Contains(t, err.Error(), "blank owner")
}

// TestParseAtBeforeOrigin verifies @ without $ORIGIN is rejected.
func TestParseAtBeforeOrigin(t *testing.T) {
	t.Parallel()
	src := "$TTL 60\n@ IN A 192.0.2.1\n"
	_, err := zonefile.Parse(strings.NewReader(src))
	require.ErrorIs(t, err, zonefile.ErrParse)
}

// TestParseRelativeNoOrigin verifies a relative name without $ORIGIN.
func TestParseRelativeNoOrigin(t *testing.T) {
	t.Parallel()
	src := "$TTL 60\nfoo IN A 192.0.2.1\n"
	_, err := zonefile.Parse(strings.NewReader(src))
	require.Error(t, err)
	require.Contains(t, err.Error(), "relative name")
}

// TestParseAbsoluteName ensures fully-qualified names parse without an origin.
func TestParseAbsoluteName(t *testing.T) {
	t.Parallel()
	src := "$TTL 60\nfoo.example.com. IN A 192.0.2.1\n"
	z, err := zonefile.Parse(strings.NewReader(src))
	require.NoError(t, err)
	require.Equal(t, "foo.example.com.", z.Records()[0].Name().String())
}

// TestParseTrailingPrevName ensures the prevName chain works across
// multiple blank-owner records.
func TestParseTrailingPrevName(t *testing.T) {
	t.Parallel()
	src := `$ORIGIN example.com.
$TTL 60
mail IN MX 10 mail.example.com.
     IN TXT "v=spf1"
     IN A 192.0.2.50
`
	z, err := zonefile.Parse(strings.NewReader(src))
	require.NoError(t, err)
	for _, r := range z.Records() {
		require.Equal(t, "mail.example.com.", r.Name().String())
	}
}

// TestSOAAccessorEmpty exercises the no-SOA branch of Zone.SOA().
func TestSOAAccessorEmpty(t *testing.T) {
	t.Parallel()
	src := minimalZone
	z, err := zonefile.Parse(strings.NewReader(src))
	require.NoError(t, err)
	_, _, ok := z.SOA()
	require.False(t, ok)
}

// TestSOAAccessorPresent exercises the success branch and accessor.
func TestSOAAccessorPresent(t *testing.T) {
	t.Parallel()
	src := `$ORIGIN example.com.
$TTL 60
@ IN SOA ns.example.com. hm.example.com. ( 7 7200 3600 1209600 60 )
@ IN A 192.0.2.1
`
	z, err := zonefile.Parse(strings.NewReader(src))
	require.NoError(t, err)
	soa, rec, ok := z.SOA()
	require.True(t, ok)
	require.Equal(t, uint32(7), soa.Serial())
	require.Equal(t, rrtype.SOA, rec.Type())
}

// TestWriteNoSOA ensures Write succeeds (without emitting $TTL) when the
// zone has no SOA.
func TestWriteNoSOA(t *testing.T) {
	t.Parallel()
	src := minimalZone
	z, err := zonefile.Parse(strings.NewReader(src))
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, zonefile.Write(&buf, z))
	out := buf.String()
	require.Contains(t, out, "$ORIGIN example.com.")
	require.NotContains(t, out, "$TTL")
}

// TestWriteSOAZeroMinimum verifies a SOA whose Minimum is zero does not
// emit a $TTL directive.
func TestWriteSOAZeroMinimum(t *testing.T) {
	t.Parallel()
	src := `$ORIGIN example.com.
$TTL 60
@ IN SOA ns. hm. ( 1 2 3 4 0 )
@ IN A 192.0.2.1
`
	z, err := zonefile.Parse(strings.NewReader(src))
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, zonefile.Write(&buf, z))
	require.NotContains(t, buf.String(), "$TTL ")
}

// errWriter always errors on Write — used to exercise error propagation
// through bufWriter.Flush.
type errWriter struct{}

func (errWriter) Write(_ []byte) (int, error) { return 0, io.ErrShortWrite }

// TestWriteFlushError verifies the writer propagates the underlying
// io.Writer error through Flush.
func TestWriteFlushError(t *testing.T) {
	t.Parallel()
	src := minimalZone
	z, err := zonefile.Parse(strings.NewReader(src))
	require.NoError(t, err)
	require.ErrorIs(t, zonefile.Write(errWriter{}, z), io.ErrShortWrite)
}

// TestWriteCAA covers the CAA branch of formatRDataPresentation.
func TestWriteCAA(t *testing.T) {
	t.Parallel()
	caa, err := rdata.NewCAA(0, "issue", []byte("letsencrypt.org"))
	require.NoError(t, err)
	owner := wire.MustParseName("example.com")
	rec := wire.NewRecordClass(owner, rrtype.ClassIN, 60*time.Second, caa)

	src := minimalZone
	z, err := zonefile.Parse(strings.NewReader(src))
	require.NoError(t, err)
	// Build a synthetic zone via parse + tack on a CAA record to drive
	// the writer's CAA branch. Use the helper.
	zsyn := &syntheticZone{origin: z.Origin(), records: append(z.Records(), rec)}
	var buf bytes.Buffer
	require.NoError(t, zonefile.Write(&buf, zsyn))
	require.Contains(t, buf.String(), "0 issue \"letsencrypt.org\"")
}

// TestWriteUnknownRData covers the RFC 3597 generic-form writer branch.
func TestWriteUnknownRData(t *testing.T) {
	t.Parallel()
	u := rdata.NewUnknown(rrtype.Type(65500), []byte{0xde, 0xad, 0xbe, 0xef})
	owner := wire.MustParseName("example.com")
	rec := wire.NewRecordClass(owner, rrtype.ClassIN, 60*time.Second, u)

	src := minimalZone
	z, err := zonefile.Parse(strings.NewReader(src))
	require.NoError(t, err)
	zsyn := &syntheticZone{origin: z.Origin(), records: append(z.Records(), rec)}
	var buf bytes.Buffer
	require.NoError(t, zonefile.Write(&buf, zsyn))
	require.Contains(t, buf.String(), "\\# 4 deadbeef")
}

// TestWriteUnsupportedRData verifies Write errors on a typed rdata not in
// formatRDataPresentation's switch (e.g. SRV).
func TestWriteUnsupportedRData(t *testing.T) {
	t.Parallel()
	srv := rdata.MustNewSRV(0, 0, 80, wire.MustParseName("host.example.com"))
	owner := wire.MustParseName("_http._tcp.example.com")
	rec := wire.NewRecordClass(owner, rrtype.ClassIN, 60*time.Second, srv)

	zsyn := &syntheticZone{
		origin:  wire.MustParseName("example.com"),
		records: []wire.Record{rec},
	}
	var buf bytes.Buffer
	err := zonefile.Write(&buf, zsyn)
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot present rdata")
}

// TestWriteNonSuffixOwner covers the relativise branch where the owner is
// neither the apex nor a child of the zone origin.
func TestWriteNonSuffixOwner(t *testing.T) {
	t.Parallel()
	owner := wire.MustParseName("foreign.invalid")
	rec := wire.NewRecordClass(owner, rrtype.ClassIN, 60*time.Second,
		rdata.MustNewA(parseAddr(t, "192.0.2.99")))
	zsyn := &syntheticZone{
		origin:  wire.MustParseName("example.com"),
		records: []wire.Record{rec},
	}
	var buf bytes.Buffer
	require.NoError(t, zonefile.Write(&buf, zsyn))
	out := buf.String()
	// Foreign name should be emitted in absolute form, not collapsed.
	require.Contains(t, out, "foreign.invalid.")
}

// TestRoundTripCNAMEPTR covers parser+writer for CNAME/PTR.
func TestRoundTripCNAMEPTR(t *testing.T) {
	t.Parallel()
	src := `$ORIGIN example.com.
$TTL 60
@   IN  SOA  ns. hm. ( 1 2 3 4 5 )
www IN  CNAME other.example.com.
ptr IN  PTR  host.example.com.
`
	z, err := zonefile.Parse(strings.NewReader(src))
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, zonefile.Write(&buf, z))
	z2, err := zonefile.Parse(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	require.Equal(t, len(z.Records()), len(z2.Records()))

	var foundCNAME, foundPTR bool
	for _, r := range z2.Records() {
		switch r.Type() {
		case rrtype.CNAME:
			foundCNAME = true
			require.Equal(t, "other.example.com.", r.RData().(rdata.CNAME).Target().String())
		case rrtype.PTR:
			foundPTR = true
			require.Equal(t, "host.example.com.", r.RData().(rdata.PTR).Target().String())
		}
	}
	require.True(t, foundCNAME)
	require.True(t, foundPTR)
}

// TestRoundTripTXTQuoting verifies TXT records with quote/backslash chars
// survive a parse → write → parse cycle byte-for-byte.
func TestRoundTripTXTQuoting(t *testing.T) {
	t.Parallel()
	src := `$ORIGIN example.com.
$TTL 60
@   IN  SOA ns. hm. ( 1 2 3 4 5 )
a   IN  TXT  "plain"
b   IN  TXT  "has \"quote\""
c   IN  TXT  "has\\back"
`
	z, err := zonefile.Parse(strings.NewReader(src))
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, zonefile.Write(&buf, z))
	z2, err := zonefile.Parse(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)

	collect := func(rrs []wire.Record) map[string]string {
		m := map[string]string{}
		for _, r := range rrs {
			if r.Type() != rrtype.TXT {
				continue
			}
			s := r.RData().(rdata.TXT).Strings()
			m[r.Name().String()] = strings.Join(s, "\x00")
		}
		return m
	}
	require.Equal(t, collect(z.Records()), collect(z2.Records()))
}

// TestParseEmptyInput ensures an empty input yields an empty zone, no
// error.
func TestParseEmptyInput(t *testing.T) {
	t.Parallel()
	z, err := zonefile.Parse(strings.NewReader(""))
	require.NoError(t, err)
	require.Empty(t, z.Records())
}

// TestParseEOFAfterToken ensures an unterminated final record (no
// trailing newline) still parses.
func TestParseEOFAfterToken(t *testing.T) {
	t.Parallel()
	src := "$ORIGIN example.com.\n$TTL 60\n@ IN A 192.0.2.1"
	z, err := zonefile.Parse(strings.NewReader(src))
	require.NoError(t, err)
	require.Len(t, z.Records(), 1)
}

// syntheticZone is a minimal Zone implementation used to drive the writer
// against records we cannot construct via the parser (CAA, Unknown, SRV).
type syntheticZone struct {
	origin  wire.Name
	records []wire.Record
}

func (z *syntheticZone) Origin() wire.Name      { return z.origin }
func (z *syntheticZone) Records() []wire.Record { return z.records }
func (z *syntheticZone) SOA() (rdata.SOA, wire.Record, bool) {
	for _, r := range z.records {
		if r.Type() == rrtype.SOA {
			return r.RData().(rdata.SOA), r, true
		}
	}
	return rdata.SOA{}, wire.Record{}, false
}

func parseAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	require.NoError(t, err)
	return a
}
