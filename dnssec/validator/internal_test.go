package validator

import (
	"context"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

func TestNameSuffixEqualOrSubdomainNonAncestor(t *testing.T) {
	t.Parallel()
	// Different parent.
	require.False(t, nameSuffixEqualOrSubdomain(
		wire.MustParseName("foo.example.com."),
		wire.MustParseName("bar.com."),
	))
	// Same labels (equal).
	require.True(t, nameSuffixEqualOrSubdomain(
		wire.MustParseName("foo.example.com."),
		wire.MustParseName("foo.example.com."),
	))
	// Subdomain.
	require.True(t, nameSuffixEqualOrSubdomain(
		wire.MustParseName("foo.example.com."),
		wire.MustParseName("example.com."),
	))
	// Root parent always covers.
	require.True(t, nameSuffixEqualOrSubdomain(
		wire.MustParseName("foo.example.com."),
		wire.RootName(),
	))
	// Sibling not covered.
	require.False(t, nameSuffixEqualOrSubdomain(
		wire.MustParseName("foo.example.com."),
		wire.MustParseName("ple.com."),
	))
}

func TestHexDigitInvalid(t *testing.T) {
	t.Parallel()
	// Valid digits.
	require.Equal(t, 0, hexDigit('0'))
	require.Equal(t, 9, hexDigit('9'))
	require.Equal(t, 10, hexDigit('a'))
	require.Equal(t, 15, hexDigit('F'))
	// Invalid.
	require.Equal(t, -1, hexDigit('g'))
	require.Equal(t, -1, hexDigit('Z'))
	require.Equal(t, -1, hexDigit(' '))
}

func TestMustHexPanicsOnInvalid(t *testing.T) {
	t.Parallel()
	require.Panics(t, func() { mustHex("zz") })
}

func TestBase32HexEncodeEmpty(t *testing.T) {
	t.Parallel()
	require.Empty(t, base32hexEncode(nil))
	require.Empty(t, base32hexEncode([]byte{}))
}

func TestBase32HexDecodeInvalidChar(t *testing.T) {
	t.Parallel()
	_, err := base32hexDecode("!")
	require.Error(t, err)
	_, err = base32hexDecode("W") // beyond V
	require.Error(t, err)
}

func TestBase32HexDecodeEmpty(t *testing.T) {
	t.Parallel()
	out, err := base32hexDecode("")
	require.NoError(t, err)
	require.Nil(t, out)
}

func TestBase32HexLowercase(t *testing.T) {
	t.Parallel()
	out, err := base32hexDecode("ab")
	require.NoError(t, err)
	require.NotEmpty(t, out)
}

func TestBytesLessAndEqual(t *testing.T) {
	t.Parallel()
	require.True(t, bytesLess([]byte{1, 2}, []byte{1, 3}))
	require.False(t, bytesLess([]byte{1, 3}, []byte{1, 2}))
	// Equal prefix, longer wins.
	require.True(t, bytesLess([]byte{1}, []byte{1, 0}))
	require.False(t, bytesLess([]byte{1, 0}, []byte{1}))
	// Equal.
	require.False(t, bytesLess([]byte{1, 2}, []byte{1, 2}))
	require.True(t, bytesEqual([]byte{1, 2}, []byte{1, 2}))
	require.False(t, bytesEqual([]byte{1}, []byte{1, 0}))
	require.False(t, bytesEqual([]byte{1, 2}, []byte{1, 3}))
}

func TestNSEC3OwnerHashErrors(t *testing.T) {
	t.Parallel()
	// Owner whose first label is invalid base32hex returns an error.
	bad := wire.MustParseName("zzzz!!.example.")
	_, err := nsec3OwnerHash(bad)
	require.Error(t, err)
}

func TestExtractNSEC3ParamsNoNSEC3(t *testing.T) {
	t.Parallel()
	_, ok := extractNSEC3Params(nil)
	require.False(t, ok)
}

func TestNextCloserNameEqualLabels(t *testing.T) {
	t.Parallel()
	// encloser is qname's parent — next-closer == qname.
	qname := wire.MustParseName("foo.example.")
	encloser := wire.MustParseName("example.")
	nc := nextCloserName(qname, encloser)
	require.True(t, nc.Equal(qname))
}

func TestWildcardOf(t *testing.T) {
	t.Parallel()
	enc := wire.MustParseName("example.com.")
	wc, err := wildcardOf(enc)
	require.NoError(t, err)
	require.True(t, wc.Equal(wire.MustParseName("*.example.com.")))
}

func TestNameCoveredByWraparound(t *testing.T) {
	t.Parallel()
	// Wraparound: owner > next in canonical order. qname > owner → covered.
	owner := wire.MustParseName("z.example.")
	next := wire.MustParseName("a.example.")
	qname := wire.MustParseName("zz.example.")
	require.True(t, nameCoveredBy(qname, owner, next))

	// Wraparound, qname between owner and next — NOT covered.
	qname2 := wire.MustParseName("m.example.")
	require.False(t, nameCoveredBy(qname2, owner, next))

	// Non-wraparound straightforward case.
	require.True(t, nameCoveredBy(
		wire.MustParseName("m.example."),
		wire.MustParseName("a.example."),
		wire.MustParseName("z.example."),
	))
}

func TestSignerOfNoRRSIG(t *testing.T) {
	t.Parallel()
	// No records at all.
	require.False(t, signerOf(nil).IsValid())
}

func TestExchangerSourceCounterOverflow(t *testing.T) {
	t.Parallel()
	// Drive nextID directly through the wrap branch.
	s := &exchangerSource{counter: 0xFFFF}
	id := s.nextID()
	require.Equal(t, uint16(1), id, "wrap should reset counter to 1")
}

func TestNSEC3MatchAndCoverNotFound(t *testing.T) {
	t.Parallel()
	params := nsec3Params{alg: 1, iterations: 0, salt: nil}
	// Empty records → nothing matches/covers.
	_, _, ok := nsec3Match(wire.MustParseName("foo.example."), params, nil)
	require.False(t, ok)
	_, _, ok = nsec3Cover(wire.MustParseName("foo.example."), params, nil)
	require.False(t, ok)
}

func TestNSEC3MatchHashTooManyIterations(t *testing.T) {
	t.Parallel()
	params := nsec3Params{alg: 1, iterations: MaxNSEC3Iterations + 1, salt: nil}
	_, _, ok := nsec3Match(wire.MustParseName("foo.example."), params, nil)
	require.False(t, ok)
	_, _, ok = nsec3Cover(wire.MustParseName("foo.example."), params, nil)
	require.False(t, ok)
}

// makeNSEC3Record fabricates an NSEC3 record with a synthetic owner hash.
func makeNSEC3Record(t *testing.T, hash, next []byte, types []rrtype.Type, flags uint8) wire.Record {
	t.Helper()
	label := base32hexEncode(hash)
	owner, err := wire.NameFromLabels(label, "example")
	require.NoError(t, err)
	return wire.NewRecord(owner, time.Hour, rdata.NewNSEC3(1, flags, 0, nil, next, types))
}

func TestNSEC3MatchSkipsNonNSEC3(t *testing.T) {
	t.Parallel()
	// Records that are not NSEC3 are ignored.
	a := wire.NewRecord(wire.MustParseName("x.example."), time.Hour,
		rdata.NewNS(wire.MustParseName("ns.example.")))
	params := nsec3Params{alg: 1, iterations: 0, salt: nil}
	_, _, ok := nsec3Match(wire.MustParseName("foo.example."), params, []wire.Record{a})
	require.False(t, ok)
	_, _, ok = nsec3Cover(wire.MustParseName("foo.example."), params, []wire.Record{a})
	require.False(t, ok)
}

func TestNSEC3MatchSucceeds(t *testing.T) {
	t.Parallel()
	params := nsec3Params{alg: 1, iterations: 0, salt: nil}
	target := wire.MustParseName("present.example.")
	hash := nsec3Hash(target, params.salt, params.iterations)
	rec := makeNSEC3Record(t, hash, hash, []rrtype.Type{rrtype.A}, 0)
	_, n3, ok := nsec3Match(target, params, []wire.Record{rec})
	require.True(t, ok)
	require.NotNil(t, n3)
}

func TestNSEC3CoverSucceeds(t *testing.T) {
	t.Parallel()
	params := nsec3Params{alg: 1, iterations: 0, salt: nil}
	target := wire.MustParseName("missing.example.")
	hash := nsec3Hash(target, params.salt, params.iterations)
	// Build a record whose interval (lo, hi) brackets hash.
	lo := make([]byte, len(hash))
	hi := make([]byte, len(hash))
	copy(lo, hash)
	copy(hi, hash)
	// Decrement lo, increment hi (clamped within byte range).
	for i := len(lo) - 1; i >= 0; i-- {
		if lo[i] > 0 {
			lo[i]--
			break
		}
		lo[i] = 0xff
	}
	for i := len(hi) - 1; i >= 0; i-- {
		if hi[i] < 0xff {
			hi[i]++
			break
		}
		hi[i] = 0
	}
	rec := makeNSEC3Record(t, lo, hi, nil, 0)
	_, _, ok := nsec3Cover(target, params, []wire.Record{rec})
	require.True(t, ok)
}

func TestNSEC3OwnerHashEmptyName(t *testing.T) {
	t.Parallel()
	// Root name has no labels → returns the no-label error path.
	_, err := nsec3OwnerHash(wire.RootName())
	require.Error(t, err)
}

func TestExtractNSEC3ParamsMismatch(t *testing.T) {
	t.Parallel()
	// Two NSEC3s with different iterations/salt → params disagree.
	r1 := wire.NewRecord(wire.MustParseName("aaa.example."), time.Hour,
		rdata.NewNSEC3(1, 0, 5, []byte{1}, make([]byte, 20), nil))
	r2 := wire.NewRecord(wire.MustParseName("bbb.example."), time.Hour,
		rdata.NewNSEC3(1, 0, 10, []byte{1}, make([]byte, 20), nil))
	_, ok := extractNSEC3Params([]wire.Record{r1, r2})
	require.False(t, ok)
}

func TestNSEC3ProveDenialNoParams(t *testing.T) {
	t.Parallel()
	res := nsec3ProveDenial(wire.MustParseName("foo.example."), rrtype.A, wire.MustParseName("example."), nil)
	require.Equal(t, nsec3DenialNone, res.kind)
}

func TestNSEC3ProveDenialIterationsTooHigh(t *testing.T) {
	t.Parallel()
	r := wire.NewRecord(wire.MustParseName("aaa.example."), time.Hour,
		rdata.NewNSEC3(1, 0, MaxNSEC3Iterations+1, nil, make([]byte, 20), nil))
	res := nsec3ProveDenial(wire.MustParseName("foo.example."), rrtype.A,
		wire.MustParseName("example."), []wire.Record{r})
	require.Equal(t, nsec3DenialNone, res.kind)
}

func TestFindNSEC3ClosestEncloserNoMatch(t *testing.T) {
	t.Parallel()
	params := nsec3Params{alg: 1, iterations: 0, salt: nil}
	enc, ok := findNSEC3ClosestEncloser(
		wire.MustParseName("foo.example."),
		wire.MustParseName("example."),
		params, nil,
	)
	require.False(t, ok)
	require.False(t, enc.IsValid())
}

// TestNSEC3ProveDenialDSNoData exercises the qtype==DS path with a matching
// NSEC3 whose bitmap has neither NS nor DS (yields NoData).
func TestNSEC3ProveDenialDSNoData(t *testing.T) {
	t.Parallel()
	params := nsec3Params{alg: 1, iterations: 0, salt: nil}
	target := wire.MustParseName("plain.example.")
	hash := nsec3Hash(target, params.salt, params.iterations)
	rec := makeNSEC3Record(t, hash, hash, []rrtype.Type{rrtype.A}, 0)
	res := nsec3ProveDenial(target, rrtype.DS, wire.MustParseName("example."), []wire.Record{rec})
	require.Equal(t, nsec3DenialNoData, res.kind)
}

// TestNSEC3ProveDenialDSInsecureDelegation: matching NSEC3 has NS but no DS.
func TestNSEC3ProveDenialDSInsecureDelegation(t *testing.T) {
	t.Parallel()
	params := nsec3Params{alg: 1, iterations: 0, salt: nil}
	target := wire.MustParseName("delegated.example.")
	hash := nsec3Hash(target, params.salt, params.iterations)
	rec := makeNSEC3Record(t, hash, hash, []rrtype.Type{rrtype.NS}, 0)
	res := nsec3ProveDenial(target, rrtype.DS, wire.MustParseName("example."), []wire.Record{rec})
	require.Equal(t, nsec3DenialInsecureDelegation, res.kind)
}

// TestNSEC3ProveDenialNoDataNonDS: non-DS NoData with matching NSEC3 lacking
// the qtype bit.
// TestHashIntervalContainsWrap exercises the wraparound branch with
// non-trivial multi-byte values.
func TestHashIntervalContainsWrap(t *testing.T) {
	t.Parallel()
	owner := []byte{0xff, 0xff}
	next := []byte{0x00, 0x10}
	// x just below next — covered (x < next).
	require.True(t, hashIntervalContains(owner, next, []byte{0x00, 0x05}))
	// x above owner is impossible since owner is max; check x in middle =
	// not covered (x is not greater than owner and not less than next).
	require.False(t, hashIntervalContains(owner, next, []byte{0x80, 0x00}))
}

// TestNSEC3ProveDenialDSOptOutCover: qtype==DS, no matching NSEC3 at qname,
// but a covering NSEC3 has the opt-out flag → opt-out outcome.
func TestNSEC3ProveDenialDSOptOutCover(t *testing.T) {
	t.Parallel()
	params := nsec3Params{alg: 1, iterations: 0, salt: nil}
	target := wire.MustParseName("missing.example.")
	hash := nsec3Hash(target, params.salt, params.iterations)
	lo := make([]byte, len(hash))
	hi := make([]byte, len(hash))
	copy(lo, hash)
	copy(hi, hash)
	for i := len(lo) - 1; i >= 0; i-- {
		if lo[i] > 0 {
			lo[i]--
			break
		}
		lo[i] = 0xff
	}
	for i := len(hi) - 1; i >= 0; i-- {
		if hi[i] < 0xff {
			hi[i]++
			break
		}
		hi[i] = 0
	}
	rec := makeNSEC3Record(t, lo, hi, nil, NSEC3FlagOptOut)
	res := nsec3ProveDenial(target, rrtype.DS, wire.MustParseName("example."), []wire.Record{rec})
	require.Equal(t, nsec3DenialOptOut, res.kind)
}

func TestNSEC3ProveDenialNoDataAAAA(t *testing.T) {
	t.Parallel()
	params := nsec3Params{alg: 1, iterations: 0, salt: nil}
	target := wire.MustParseName("plain.example.")
	hash := nsec3Hash(target, params.salt, params.iterations)
	rec := makeNSEC3Record(t, hash, hash, []rrtype.Type{rrtype.A}, 0)
	res := nsec3ProveDenial(target, rrtype.AAAA, wire.MustParseName("example."), []wire.Record{rec})
	require.Equal(t, nsec3DenialNoData, res.kind)
}

func TestRRsigValidNowWithSkewBranches(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	// Build a synthetic RRSIG via constructor.
	// NewRRSIG signature is (typeCovered, alg, labels, origTTL, expiration, inception, ...)
	sig := rdata.NewRRSIG(rrtype.A, rdata.AlgECDSAP256SHA256, 2, time.Hour,
		now.Add(time.Hour), now.Add(-time.Hour),
		1, wire.MustParseName("example."), nil)
	require.True(t, rrsigValidNowWithSkew(sig, now, 0))
	// Before inception even with skew.
	require.False(t, rrsigValidNowWithSkew(sig, now.Add(-2*time.Hour), 0))
	// After expiration even with skew.
	require.False(t, rrsigValidNowWithSkew(sig, now.Add(2*time.Hour), 0))
	// Inside skew bring in.
	require.True(t, rrsigValidNowWithSkew(sig, now.Add(-90*time.Minute), time.Hour))
	require.True(t, rrsigValidNowWithSkew(sig, now.Add(90*time.Minute), time.Hour))
}

func TestRecordsOfTypeFiltersTypeAndOwner(t *testing.T) {
	t.Parallel()
	owner := wire.MustParseName("foo.example.")
	other := wire.MustParseName("bar.example.")
	r1 := wire.NewRecord(owner, time.Hour, rdata.NewNS(wire.MustParseName("ns.foo.example.")))
	r2 := wire.NewRecord(other, time.Hour, rdata.NewNS(wire.MustParseName("ns.bar.example.")))
	r3 := wire.NewRecord(owner, time.Hour, rdata.NewNS(wire.MustParseName("ns2.foo.example.")))
	got := recordsOfType([]wire.Record{r1, r2, r3}, rrtype.NS, owner)
	require.Len(t, got, 2)

	// Type mismatch path.
	got = recordsOfType([]wire.Record{r1, r2, r3}, rrtype.MX, owner)
	require.Empty(t, got)
}

func TestGroupRecordsByOwnerAppend(t *testing.T) {
	t.Parallel()
	a := wire.NewRecord(wire.MustParseName("a.example."), time.Hour, rdata.NewNS(wire.MustParseName("ns1.example.")))
	a2 := wire.NewRecord(wire.MustParseName("a.example."), time.Hour, rdata.NewNS(wire.MustParseName("ns2.example.")))
	b := wire.NewRecord(wire.MustParseName("b.example."), time.Hour, rdata.NewNS(wire.MustParseName("ns3.example.")))
	groups := groupRecordsByOwner([]wire.Record{a, b, a2})
	require.Len(t, groups, 2)
	// First group is a.example. with two records.
	require.Len(t, groups[0], 2)
}

func TestGroupNSECByOwnerAppend(t *testing.T) {
	t.Parallel()
	a := wire.NewRecord(wire.MustParseName("a.example."), time.Hour,
		rdata.NewNSEC(wire.MustParseName("b.example."), nil))
	a2 := wire.NewRecord(wire.MustParseName("a.example."), time.Hour,
		rdata.NewNSEC(wire.MustParseName("c.example."), nil))
	b := wire.NewRecord(wire.MustParseName("b.example."), time.Hour,
		rdata.NewNSEC(wire.MustParseName("c.example."), nil))
	groups := groupNSECByOwner([]wire.Record{a, b, a2})
	require.Len(t, groups, 2)
	require.Len(t, groups[0], 2)
}

func TestFilterNSECByOwner(t *testing.T) {
	t.Parallel()
	a := wire.NewRecord(wire.MustParseName("a.example."), time.Hour,
		rdata.NewNSEC(wire.MustParseName("b.example."), nil))
	other := wire.NewRecord(wire.MustParseName("z.example."), time.Hour,
		rdata.NewNSEC(wire.MustParseName("zz.example."), nil))
	notNSEC := wire.NewRecord(wire.MustParseName("a.example."), time.Hour,
		rdata.NewNS(wire.MustParseName("ns.example.")))
	got := filterNSECByOwner([]wire.Record{a, other, notNSEC}, wire.MustParseName("a.example."))
	require.Len(t, got, 1)
}

func TestCanonicalNameCmpEqualLength(t *testing.T) {
	t.Parallel()
	a := wire.MustParseName("foo.example.")
	require.Equal(t, 0, canonicalNameCmp(a, a))
}

func TestSignerOfReturnsRRSIGSigner(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	sig := rdata.NewRRSIG(rrtype.A, rdata.AlgECDSAP256SHA256, 2, time.Hour,
		now.Add(time.Hour), now,
		1, wire.MustParseName("example."), nil)
	rec := wire.NewRecord(wire.MustParseName("foo.example."), time.Hour, sig)
	notSig := wire.NewRecord(wire.MustParseName("a.example."), time.Hour,
		rdata.NewNS(wire.MustParseName("ns.example.")))
	require.True(t, signerOf([]wire.Record{notSig, rec}).Equal(wire.MustParseName("example.")))
}

func TestBase32HexEncodeOddBytes(t *testing.T) {
	t.Parallel()
	// 1 byte = 8 bits → 2 base32hex chars (5+3 leftover).
	require.Equal(t, "00", base32hexEncode([]byte{0}))
	// 3 bytes = 24 bits → 5 base32hex chars (5*4=20 + 4 leftover).
	enc := base32hexEncode([]byte{0xff, 0xff, 0xff})
	require.NotEmpty(t, enc)
}

func TestExchangerSourceLookupBuildErrorPathUnreachable(t *testing.T) {
	t.Parallel()
	// The build-error path inside Lookup is effectively unreachable with
	// a valid wire.Question — but we can still drive the success path
	// through with various option combinations to cover the remainder.
	qname := wire.MustParseName("foo.example.")
	resp, _ := wire.NewBuilder().ID(1).Response(true).
		RCODE(wire.RCODENoError).
		Question(wire.NewQuestion(qname, rrtype.A)).
		Build()
	ex := &recordingExchangerInternal{resp: resp}
	src := NewExchangerSource(ex,
		WithExchangerSourceUDPSize(4096),
	)
	_, err := src.Lookup(t.Context(), qname, rrtype.A)
	require.NoError(t, err)
}

type recordingExchangerInternal struct {
	resp wire.Message
}

func (r *recordingExchangerInternal) Exchange(_ context.Context, _ wire.Message) (wire.Message, error) {
	return r.resp, nil
}

func TestTruncateNameTo(t *testing.T) {
	t.Parallel()
	n := wire.MustParseName("a.b.c.example.")
	// Truncate to 2 labels (root + "example.")
	got := truncateNameTo(n, 2)
	require.True(t, got.Equal(wire.MustParseName("c.example.")))
	// k larger than NumLabels — return unchanged.
	got = truncateNameTo(n, 100)
	require.True(t, got.Equal(n))
	// k=1 → "example."
	got = truncateNameTo(n, 1)
	require.True(t, got.Equal(wire.MustParseName("example.")))
	// k=0 → root.
	got = truncateNameTo(n, 0)
	require.True(t, got.Equal(wire.RootName()))
}
