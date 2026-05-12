package zonefile_test

import (
	"strings"
	"testing"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/zonefile"
	"github.com/stretchr/testify/require"
)

const generateHeader = `$ORIGIN example.com.
$TTL 60
`

// TestGeneratePTRFanOut covers the most common production use:
// expanding a /24 reverse-zone PTR sweep.
func TestGeneratePTRFanOut(t *testing.T) {
	t.Parallel()
	src := generateHeader + `$GENERATE 1-3 $ PTR host-$.example.com.
`
	z, err := zonefile.Parse(strings.NewReader(src))
	require.NoError(t, err)
	recs := z.Records()
	require.Equal(t, 3, len(recs))
	wantOwners := []string{"1.example.com.", "2.example.com.", "3.example.com."}
	wantTargets := []string{"host-1.example.com.", "host-2.example.com.", "host-3.example.com."}
	for i, rec := range recs {
		require.Equal(t, rrtype.PTR, rec.Type())
		require.Equal(t, wantOwners[i], rec.Name().String())
		ptr, ok := wire.RDataAs[rdata.PTR](rec)
		require.True(t, ok)
		require.Equal(t, wantTargets[i], ptr.Target().String())
	}
}

func TestGenerateWidthZeroPad(t *testing.T) {
	t.Parallel()
	src := generateHeader + `$GENERATE 0-2 host-${0,3,d} A 10.0.0.$
`
	z, err := zonefile.Parse(strings.NewReader(src))
	require.NoError(t, err)
	recs := z.Records()
	require.Equal(t, 3, len(recs))
	want := []string{"host-000.example.com.", "host-001.example.com.", "host-002.example.com."}
	for i, rec := range recs {
		require.Equal(t, want[i], rec.Name().String())
		a, ok := wire.RDataAs[rdata.A](rec)
		require.True(t, ok)
		require.Equal(t, "10.0.0."+string(rune('0'+i)), a.Addr().String())
	}
}

func TestGenerateStep(t *testing.T) {
	t.Parallel()
	src := generateHeader + `$GENERATE 0-10/2 host-$ A 10.0.0.$
`
	z, err := zonefile.Parse(strings.NewReader(src))
	require.NoError(t, err)
	require.Equal(t, 6, len(z.Records())) // 0, 2, 4, 6, 8, 10
}

func TestGenerateOffset(t *testing.T) {
	t.Parallel()
	src := generateHeader + `$GENERATE 1-3 host-${10} A 10.0.0.$
`
	z, err := zonefile.Parse(strings.NewReader(src))
	require.NoError(t, err)
	want := []string{"host-11.example.com.", "host-12.example.com.", "host-13.example.com."}
	for i, rec := range z.Records() {
		require.Equal(t, want[i], rec.Name().String())
	}
}

func TestGenerateHexFormat(t *testing.T) {
	t.Parallel()
	// Owner names canonicalise to lowercase (RFC 4343), so the upper-case
	// format is exercised in the TXT rdata instead.
	src := generateHeader + `$GENERATE 10-12 host-${0,2,x} TXT "${0,2,X}"
`
	z, err := zonefile.Parse(strings.NewReader(src))
	require.NoError(t, err)
	recs := z.Records()
	require.Equal(t, 3, len(recs))
	wantOwner := []string{"host-0a.example.com.", "host-0b.example.com.", "host-0c.example.com."}
	wantTXT := []string{"0A", "0B", "0C"}
	for i, rec := range recs {
		require.Equal(t, wantOwner[i], rec.Name().String())
		txt, ok := wire.RDataAs[rdata.TXT](rec)
		require.True(t, ok)
		require.Equal(t, wantTXT[i], txt.Strings()[0])
	}
}

func TestGenerateOctalFormat(t *testing.T) {
	t.Parallel()
	src := generateHeader + `$GENERATE 8-10 host-${0,3,o} A 10.0.0.$
`
	z, err := zonefile.Parse(strings.NewReader(src))
	require.NoError(t, err)
	want := []string{"host-010.example.com.", "host-011.example.com.", "host-012.example.com."}
	for i, rec := range z.Records() {
		require.Equal(t, want[i], rec.Name().String())
	}
}

func TestGenerateEscapedDollar(t *testing.T) {
	t.Parallel()
	// `\$` is consumed by the quoted-string lexer (RFC 1035 §5.1 escape),
	// so a TXT body that needs a literal `$` reaching $GENERATE writes
	// `\\$`: the lexer yields `\$`, the substitution engine then yields
	// `$`. Outside of quotes the single-backslash form suffices because
	// the lexer treats unquoted text verbatim.
	src := generateHeader + `$GENERATE 1-2 a-$ TXT "literal-\\$"
`
	z, err := zonefile.Parse(strings.NewReader(src))
	require.NoError(t, err)
	require.Equal(t, 2, len(z.Records()))
	for _, rec := range z.Records() {
		txt, ok := wire.RDataAs[rdata.TXT](rec)
		require.True(t, ok)
		require.Equal(t, "literal-$", txt.Strings()[0])
	}
}

func TestGenerateExplicitTTLAndClass(t *testing.T) {
	t.Parallel()
	src := generateHeader + `$GENERATE 1-2 host-$ 300 IN A 10.0.0.$
`
	z, err := zonefile.Parse(strings.NewReader(src))
	require.NoError(t, err)
	require.Equal(t, 2, len(z.Records()))
	for _, rec := range z.Records() {
		require.Equal(t, 300, int(rec.TTL().Seconds()))
	}
}

func TestGenerateMXRDataMultiToken(t *testing.T) {
	t.Parallel()
	src := generateHeader + `$GENERATE 1-2 host-$ MX 10 mail$.example.com.
`
	z, err := zonefile.Parse(strings.NewReader(src))
	require.NoError(t, err)
	require.Equal(t, 2, len(z.Records()))
	mx0, ok := wire.RDataAs[rdata.MX](z.Records()[0])
	require.True(t, ok)
	require.Equal(t, "mail1.example.com.", mx0.Exchange().String())
	require.Equal(t, uint16(10), mx0.Preference())
}

func TestGenerateRejectsBadRange(t *testing.T) {
	t.Parallel()
	cases := []string{
		"$GENERATE 5-1 host-$ A 10.0.0.$\n",  // stop < start
		"$GENERATE 1 host-$ A 10.0.0.$\n",    // missing stop
		"$GENERATE -1-3 host-$ A 10.0.0.$\n", // negative start
		"$GENERATE 1-5/0 host-$ A 10.0.0.$\n", // zero step
		"$GENERATE 1-5/-1 host-$ A 10.0.0.$\n", // negative step
		"$GENERATE x-5 host-$ A 10.0.0.$\n",   // non-integer start
	}
	for _, c := range cases {
		_, err := zonefile.Parse(strings.NewReader(generateHeader + c))
		require.Error(t, err, "case: %s", c)
	}
}

func TestGenerateIterationCap(t *testing.T) {
	t.Parallel()
	src := generateHeader + `$GENERATE 0-100 host-$ A 10.0.0.$
`
	_, err := zonefile.Parse(strings.NewReader(src), zonefile.WithGenerateMaxIterations(50))
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds cap")
}

func TestGenerateUnterminatedBrace(t *testing.T) {
	t.Parallel()
	src := generateHeader + `$GENERATE 1-2 host-${0,2 A 10.0.0.$
`
	_, err := zonefile.Parse(strings.NewReader(src))
	require.Error(t, err)
}

func TestGenerateUnsupportedFormat(t *testing.T) {
	t.Parallel()
	src := generateHeader + `$GENERATE 1-2 host-${0,3,n} A 10.0.0.$
`
	_, err := zonefile.Parse(strings.NewReader(src))
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported format")
}
