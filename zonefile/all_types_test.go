package zonefile_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/zonefile"
	"github.com/stretchr/testify/require"
)

func TestParseAllRRTypes(t *testing.T) {
	t.Parallel()
	src := `$ORIGIN example.com.
$TTL 60
@     IN  SOA   ns. hm. ( 1 7200 3600 1209600 60 )
@     IN  NS    ns1.example.com.
ns1   IN  A     192.0.2.10
v6    IN  AAAA  2001:db8::1
www   IN  CNAME other.example.com.
ptr   IN  PTR   host.example.com.
mx    IN  MX    10 mail.example.com.
txt   IN  TXT   "hello" "world"
_sip._tcp IN SRV 10 60 5060 sipsvr.example.com.
@     IN  CAA   0 issue "letsencrypt.org"
old   IN  DNAME new.example.com.
@     IN  DS    12345 13 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
@     IN  DNSKEY 257 3 13 AAAAB3NzaC1yc2EAAAADAQABAAABAQ==
`
	z, err := zonefile.Parse(strings.NewReader(src))
	require.NoError(t, err)
	require.Greater(t, len(z.Records()), 10)
}

func TestParseQuotedTXT(t *testing.T) {
	t.Parallel()
	src := `$ORIGIN example.com.
$TTL 60
@ IN TXT "with \"escaped\" quotes"
`
	_, err := zonefile.Parse(strings.NewReader(src))
	require.NoError(t, err)
}

// TestQuotedDecimalEscape covers RFC 1035 §5.1 \DDD inside quoted
// strings (added for SEC-ZO-1). Prior to the fix, the lexer accepted
// \X (X non-digit) but silently treated \DDD as three independent
// characters, dropping the backslash and emitting the digits literally.
func TestQuotedDecimalEscape(t *testing.T) {
	t.Parallel()
	header := "$ORIGIN example.com.\n$TTL 60\n"

	t.Run("octal byte 0x01", func(t *testing.T) {
		t.Parallel()
		z, err := zonefile.Parse(strings.NewReader(header + `@ IN TXT "\001"` + "\n"))
		require.NoError(t, err)
		require.Len(t, z.Records(), 1)
		txt, ok := wire.RDataAs[rdata.TXT](z.Records()[0])
		require.True(t, ok)
		require.Equal(t, []string{"\x01"}, txt.Strings())
	})

	t.Run("decimal 46 is literal dot inside TXT character-string", func(t *testing.T) {
		t.Parallel()
		// `\046` is byte 0x2e. In a TXT character-string the lexer
		// must produce a single string containing `.`, not split on
		// it — quoted strings are opaque to the wire-name parser.
		z, err := zonefile.Parse(strings.NewReader(header + `@ IN TXT "foo\046bar"` + "\n"))
		require.NoError(t, err)
		require.Len(t, z.Records(), 1)
		txt, ok := wire.RDataAs[rdata.TXT](z.Records()[0])
		require.True(t, ok)
		require.Equal(t, []string{"foo.bar"}, txt.Strings())
	})

	t.Run("mixed escape forms", func(t *testing.T) {
		t.Parallel()
		// \" stays as literal quote (\X form); \092 is byte 0x5c (`\`)
		// via the decimal form.
		z, err := zonefile.Parse(strings.NewReader(header + `@ IN TXT "a\"b\092c"` + "\n"))
		require.NoError(t, err)
		txt, ok := wire.RDataAs[rdata.TXT](z.Records()[0])
		require.True(t, ok)
		require.Equal(t, []string{`a"b\c`}, txt.Strings())
	})

	t.Run("truncated decimal escape errors", func(t *testing.T) {
		t.Parallel()
		_, err := zonefile.Parse(strings.NewReader(header + `@ IN TXT "\99"` + "\n"))
		require.Error(t, err)
	})

	t.Run("decimal escape > 255 errors", func(t *testing.T) {
		t.Parallel()
		_, err := zonefile.Parse(strings.NewReader(header + `@ IN TXT "\999"` + "\n"))
		require.Error(t, err)
	})
}

// TestTXTRoundTripBinaryBytes round-trips a TXT record whose
// character-string covers every byte 0..255 — split across two strings
// to honour the 255-byte RFC 1035 §3.3.14 cap on a single character-
// string. The reader must decode `\DDD` to the original byte; the
// writer must emit non-printable bytes as `\DDD` so the second parse
// can recover them. SEC-ZO-1 regression.
func TestTXTRoundTripBinaryBytes(t *testing.T) {
	t.Parallel()
	encode := func(b []byte) string {
		var sb strings.Builder
		sb.WriteByte('"')
		for _, c := range b {
			switch {
			case c == '"' || c == '\\':
				sb.WriteByte('\\')
				sb.WriteByte(c)
			case c < 0x20 || c > 0x7e:
				sb.WriteByte('\\')
				sb.WriteString(decimalPad3(c))
			default:
				sb.WriteByte(c)
			}
		}
		sb.WriteByte('"')
		return sb.String()
	}
	var first, second [128]byte
	for i := range 128 {
		first[i] = byte(i)
		second[i] = byte(128 + i)
	}
	src := "$ORIGIN example.com.\n$TTL 60\n@ IN TXT " +
		encode(first[:]) + " " + encode(second[:]) + "\n"

	z1, err := zonefile.Parse(strings.NewReader(src))
	require.NoError(t, err)
	require.Len(t, z1.Records(), 1)
	t1, ok := wire.RDataAs[rdata.TXT](z1.Records()[0])
	require.True(t, ok)
	require.Equal(t, []string{string(first[:]), string(second[:])}, t1.Strings())

	var buf bytes.Buffer
	require.NoError(t, zonefile.Write(&buf, z1))

	z2, err := zonefile.Parse(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	require.Len(t, z2.Records(), 1)
	t2, ok := wire.RDataAs[rdata.TXT](z2.Records()[0])
	require.True(t, ok)
	require.Equal(t, t1.Strings(), t2.Strings())
}

func decimalPad3(b byte) string {
	var out [3]byte
	out[0] = '0' + b/100
	out[1] = '0' + (b/10)%10
	out[2] = '0' + b%10
	return string(out[:])
}

func TestParseInvalidNS(t *testing.T) {
	t.Parallel()
	_, err := zonefile.Parse(strings.NewReader("$ORIGIN example.com.\n$TTL 60\n@ IN NS not a name\n"))
	require.Error(t, err)
}

func TestParseUnknownType(t *testing.T) {
	t.Parallel()
	_, err := zonefile.Parse(strings.NewReader("$ORIGIN example.com.\n$TTL 60\n@ IN UNKNOWNRRTYPE foo\n"))
	require.Error(t, err)
}
