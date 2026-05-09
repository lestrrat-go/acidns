package validatorbb_test

import (
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnssec/validator/validatorbb"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

func TestNameSuffixEqualOrSubdomainNonAncestor(t *testing.T) {
	t.Parallel()
	// Different parent.
	require.False(t, validatorbb.NameSuffixEqualOrSubdomain(
		wire.MustParseName("foo.example.com."),
		wire.MustParseName("bar.com."),
	))
	// Same labels (equal).
	require.True(t, validatorbb.NameSuffixEqualOrSubdomain(
		wire.MustParseName("foo.example.com."),
		wire.MustParseName("foo.example.com."),
	))
	// Subdomain.
	require.True(t, validatorbb.NameSuffixEqualOrSubdomain(
		wire.MustParseName("foo.example.com."),
		wire.MustParseName("example.com."),
	))
	// Root parent always covers.
	require.True(t, validatorbb.NameSuffixEqualOrSubdomain(
		wire.MustParseName("foo.example.com."),
		wire.RootName(),
	))
	// Sibling not covered.
	require.False(t, validatorbb.NameSuffixEqualOrSubdomain(
		wire.MustParseName("foo.example.com."),
		wire.MustParseName("ple.com."),
	))
}

func TestHexDigitInvalid(t *testing.T) {
	t.Parallel()
	// Valid digits.
	require.Equal(t, 0, validatorbb.HexDigit('0'))
	require.Equal(t, 9, validatorbb.HexDigit('9'))
	require.Equal(t, 10, validatorbb.HexDigit('a'))
	require.Equal(t, 15, validatorbb.HexDigit('F'))
	// Invalid.
	require.Equal(t, -1, validatorbb.HexDigit('g'))
	require.Equal(t, -1, validatorbb.HexDigit('Z'))
	require.Equal(t, -1, validatorbb.HexDigit(' '))
}

func TestMustHexPanicsOnInvalid(t *testing.T) {
	t.Parallel()
	require.Panics(t, func() { validatorbb.MustHex("zz") })
}

func TestMustHexValid(t *testing.T) {
	t.Parallel()
	require.Equal(t, []byte{0xab, 0xcd, 0xef}, validatorbb.MustHex("abcdef"))
	require.Equal(t, []byte{0x00, 0xff}, validatorbb.MustHex("00FF"))
	// Empty input → empty slice.
	require.Empty(t, validatorbb.MustHex(""))
}

func TestBase32HexEncodeEmpty(t *testing.T) {
	t.Parallel()
	require.Empty(t, validatorbb.Base32HexEncode(nil))
	require.Empty(t, validatorbb.Base32HexEncode([]byte{}))
}

func TestBase32HexDecodeInvalidChar(t *testing.T) {
	t.Parallel()
	_, err := validatorbb.Base32HexDecode("!")
	require.ErrorContains(t, err, "base32hex")
	_, err = validatorbb.Base32HexDecode("W") // beyond V
	require.ErrorContains(t, err, "base32hex")
}

func TestBase32HexDecodeEmpty(t *testing.T) {
	t.Parallel()
	out, err := validatorbb.Base32HexDecode("")
	require.NoError(t, err)
	require.Nil(t, out)
}

func TestBase32HexLowercase(t *testing.T) {
	t.Parallel()
	out, err := validatorbb.Base32HexDecode("ab")
	require.NoError(t, err)
	require.NotEmpty(t, out)
}

func TestBase32HexEncodeOddBytes(t *testing.T) {
	t.Parallel()
	// 1 byte = 8 bits → 2 base32hex chars (5+3 leftover).
	require.Equal(t, "00", validatorbb.Base32HexEncode([]byte{0}))
	// 3 bytes = 24 bits → 5 base32hex chars (5*4=20 + 4 leftover).
	enc := validatorbb.Base32HexEncode([]byte{0xff, 0xff, 0xff})
	require.NotEmpty(t, enc)
}

func TestBytesLess(t *testing.T) {
	t.Parallel()
	require.True(t, validatorbb.BytesLess([]byte{1, 2}, []byte{1, 3}))
	require.False(t, validatorbb.BytesLess([]byte{1, 3}, []byte{1, 2}))
	// Equal prefix, longer wins.
	require.True(t, validatorbb.BytesLess([]byte{1}, []byte{1, 0}))
	require.False(t, validatorbb.BytesLess([]byte{1, 0}, []byte{1}))
	// Equal.
	require.False(t, validatorbb.BytesLess([]byte{1, 2}, []byte{1, 2}))
}

func TestNextCloserNameEqualLabels(t *testing.T) {
	t.Parallel()
	// encloser is qname's parent — next-closer == qname.
	qname := wire.MustParseName("foo.example.")
	encloser := wire.MustParseName("example.")
	nc := validatorbb.NextCloserName(qname, encloser)
	require.True(t, nc.Equal(qname))
}

func TestWildcardOf(t *testing.T) {
	t.Parallel()
	enc := wire.MustParseName("example.com.")
	wc, err := validatorbb.WildcardOf(enc)
	require.NoError(t, err)
	require.True(t, wc.Equal(wire.MustParseName("*.example.com.")))
}

func TestNameCoveredByWraparound(t *testing.T) {
	t.Parallel()
	// Wraparound: owner > next in canonical order. qname > owner → covered.
	owner := wire.MustParseName("z.example.")
	next := wire.MustParseName("a.example.")
	qname := wire.MustParseName("zz.example.")
	require.True(t, validatorbb.NameCoveredBy(qname, owner, next))

	// Wraparound, qname between owner and next — NOT covered.
	qname2 := wire.MustParseName("m.example.")
	require.False(t, validatorbb.NameCoveredBy(qname2, owner, next))

	// Non-wraparound straightforward case.
	require.True(t, validatorbb.NameCoveredBy(
		wire.MustParseName("m.example."),
		wire.MustParseName("a.example."),
		wire.MustParseName("z.example."),
	))
}

func TestSignerOfNoRRSIG(t *testing.T) {
	t.Parallel()
	// No records at all.
	require.False(t, validatorbb.SignerOf(nil).IsValid())
}

func TestHashIntervalContainsWrap(t *testing.T) {
	t.Parallel()
	owner := []byte{0xff, 0xff}
	next := []byte{0x00, 0x10}
	// x just below next — covered (x < next).
	require.True(t, validatorbb.HashIntervalContains(owner, next, []byte{0x00, 0x05}))
	// x above owner is impossible since owner is max; check x in middle =
	// not covered (x is not greater than owner and not less than next).
	require.False(t, validatorbb.HashIntervalContains(owner, next, []byte{0x80, 0x00}))
}

func TestHashIntervalContainsNonWrap(t *testing.T) {
	t.Parallel()
	require.True(t, validatorbb.HashIntervalContains([]byte{10}, []byte{20}, []byte{15}))
	require.False(t, validatorbb.HashIntervalContains([]byte{10}, []byte{20}, []byte{25}))
	// Endpoints excluded.
	require.False(t, validatorbb.HashIntervalContains([]byte{10}, []byte{20}, []byte{10}))
	require.False(t, validatorbb.HashIntervalContains([]byte{10}, []byte{20}, []byte{20}))
}

func TestRRSIGValidNowWithSkewBranches(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	// Build a synthetic RRSIG via constructor.
	// NewRRSIG signature is (typeCovered, alg, labels, origTTL, expiration, inception, ...)
	sig := rdata.NewRRSIG(rrtype.A, rdata.AlgECDSAP256SHA256, 2, time.Hour,
		now.Add(time.Hour), now.Add(-time.Hour),
		1, wire.MustParseName("example."), nil)
	require.True(t, validatorbb.RRSIGValidNowWithSkew(sig, now, 0))
	// Before inception even with skew.
	require.False(t, validatorbb.RRSIGValidNowWithSkew(sig, now.Add(-2*time.Hour), 0))
	// After expiration even with skew.
	require.False(t, validatorbb.RRSIGValidNowWithSkew(sig, now.Add(2*time.Hour), 0))
	// Inside skew bring in.
	require.True(t, validatorbb.RRSIGValidNowWithSkew(sig, now.Add(-90*time.Minute), time.Hour))
	require.True(t, validatorbb.RRSIGValidNowWithSkew(sig, now.Add(90*time.Minute), time.Hour))
}

func TestRecordsOfTypeFiltersTypeAndOwner(t *testing.T) {
	t.Parallel()
	owner := wire.MustParseName("foo.example.")
	other := wire.MustParseName("bar.example.")
	r1 := wire.NewRecord(owner, time.Hour, rdata.MustNewNS(wire.MustParseName("ns.foo.example.")))
	r2 := wire.NewRecord(other, time.Hour, rdata.MustNewNS(wire.MustParseName("ns.bar.example.")))
	r3 := wire.NewRecord(owner, time.Hour, rdata.MustNewNS(wire.MustParseName("ns2.foo.example.")))
	got := validatorbb.RecordsOfType([]wire.Record{r1, r2, r3}, rrtype.NS, owner)
	require.Len(t, got, 2)

	// Type mismatch path.
	got = validatorbb.RecordsOfType([]wire.Record{r1, r2, r3}, rrtype.MX, owner)
	require.Empty(t, got)
}

func TestGroupRecordsByOwnerAppend(t *testing.T) {
	t.Parallel()
	a := wire.NewRecord(wire.MustParseName("a.example."), time.Hour, rdata.MustNewNS(wire.MustParseName("ns1.example.")))
	a2 := wire.NewRecord(wire.MustParseName("a.example."), time.Hour, rdata.MustNewNS(wire.MustParseName("ns2.example.")))
	b := wire.NewRecord(wire.MustParseName("b.example."), time.Hour, rdata.MustNewNS(wire.MustParseName("ns3.example.")))
	groups := validatorbb.GroupRecordsByOwner([]wire.Record{a, b, a2})
	require.Len(t, groups, 2)
	// First group is a.example. with two records.
	require.Len(t, groups[0], 2)
}

func TestFilterNSECByOwner(t *testing.T) {
	t.Parallel()
	a := wire.NewRecord(wire.MustParseName("a.example."), time.Hour,
		rdata.NewNSEC(wire.MustParseName("b.example."), nil))
	other := wire.NewRecord(wire.MustParseName("z.example."), time.Hour,
		rdata.NewNSEC(wire.MustParseName("zz.example."), nil))
	notNSEC := wire.NewRecord(wire.MustParseName("a.example."), time.Hour,
		rdata.MustNewNS(wire.MustParseName("ns.example.")))
	got := validatorbb.FilterNSECByOwner([]wire.Record{a, other, notNSEC}, wire.MustParseName("a.example."))
	require.Len(t, got, 1)
}

func TestCanonicalNameCmpEqualLength(t *testing.T) {
	t.Parallel()
	a := wire.MustParseName("foo.example.")
	require.Equal(t, 0, validatorbb.CanonicalNameCmp(a, a))
}

func TestCanonicalNameCmpOrdering(t *testing.T) {
	t.Parallel()
	a := wire.MustParseName("a.example.")
	b := wire.MustParseName("b.example.")
	require.Less(t, validatorbb.CanonicalNameCmp(a, b), 0)
	require.Greater(t, validatorbb.CanonicalNameCmp(b, a), 0)
	// Shorter prefix sorts before longer.
	parent := wire.MustParseName("example.")
	child := wire.MustParseName("sub.example.")
	require.Less(t, validatorbb.CanonicalNameCmp(parent, child), 0)
}

func TestSignerOfReturnsRRSIGSigner(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	sig := rdata.NewRRSIG(rrtype.A, rdata.AlgECDSAP256SHA256, 2, time.Hour,
		now.Add(time.Hour), now,
		1, wire.MustParseName("example."), nil)
	rec := wire.NewRecord(wire.MustParseName("foo.example."), time.Hour, sig)
	notSig := wire.NewRecord(wire.MustParseName("a.example."), time.Hour,
		rdata.MustNewNS(wire.MustParseName("ns.example.")))
	require.True(t, validatorbb.SignerOf([]wire.Record{notSig, rec}).Equal(wire.MustParseName("example.")))
}

func TestTruncateNameTo(t *testing.T) {
	t.Parallel()
	n := wire.MustParseName("a.b.c.example.")
	// Truncate to 2 labels (root + "example.")
	got := validatorbb.TruncateNameTo(n, 2)
	require.True(t, got.Equal(wire.MustParseName("c.example.")))
	// k larger than NumLabels — return unchanged.
	got = validatorbb.TruncateNameTo(n, 100)
	require.True(t, got.Equal(n))
	// k=1 → "example."
	got = validatorbb.TruncateNameTo(n, 1)
	require.True(t, got.Equal(wire.MustParseName("example.")))
	// k=0 → root.
	got = validatorbb.TruncateNameTo(n, 0)
	require.True(t, got.Equal(wire.RootName()))
}
