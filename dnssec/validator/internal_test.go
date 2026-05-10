package validator

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnssec/validator/validatorbb"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// TestSigningAlgorithmsFromChain verifies that the parent DS algorithms
// driving the RFC 6840 §5.11 algorithm-completeness check are pulled
// from the deepest secured zone, and that an Insecure tail step is
// skipped (Insecure subtrees do not constrain answer signing).
func TestSigningAlgorithmsFromChain(t *testing.T) {
	t.Parallel()
	chain := []ChainStep{
		chainStep{zone: wire.MustParseName("."), dss: []rdata.DS{
			fakeDS(rdata.AlgRSASHA256),
		}, res: Secure},
		chainStep{zone: wire.MustParseName("example."), dss: []rdata.DS{
			fakeDS(rdata.AlgECDSAP256SHA256),
			fakeDS(rdata.AlgED25519),
		}, res: Secure},
		chainStep{zone: wire.MustParseName("sub.example."), res: Insecure},
	}
	algs := signingAlgorithms(chain)
	require.Len(t, algs, 2)
	_, ok := algs[rdata.AlgECDSAP256SHA256]
	require.True(t, ok)
	_, ok = algs[rdata.AlgED25519]
	require.True(t, ok)
	_, ok = algs[rdata.AlgRSASHA256]
	require.False(t, ok, "deeper secure step shadows the root anchor's algs")
}

func fakeDS(alg rdata.DNSSECAlgorithm) rdata.DS {
	return rdata.NewDS(0, alg, rdata.DigestSHA256, []byte{0})
}

// TestVerifyRRsetAllAlgsRejectsMissingAlgorithm constructs an answer
// whose only RRSIG is from the weaker of two parent-DS algorithms; the
// stripped algorithm causes algorithm-completeness to fail Bogus, even
// though the surviving RRSIG would otherwise verify on its own.
func TestVerifyRRsetAllAlgsRejectsMissingAlgorithm(t *testing.T) {
	t.Parallel()
	// Empty inputs short-circuit on the "no required algs" path; the
	// missing-algorithm guard fires when requiredAlgs is non-empty and
	// no sig of that algorithm produces a successful verification.
	w := &walker{maxRRSIGsTry: 4, now: time.Now}
	required := map[rdata.DNSSECAlgorithm]struct{}{
		rdata.AlgRSASHA256:       {},
		rdata.AlgECDSAP256SHA256: {},
	}
	// One placeholder record so the "empty rrset" guard does not fire
	// before we reach the algorithm-coverage check.
	rec := wire.NewRecord(wire.MustParseName("example."), 0,
		rdata.MustNewA(netip.MustParseAddr("192.0.2.1")))
	err := w.verifyRRsetAllAlgs([]wire.Record{rec}, nil, nil, required)
	require.ErrorIs(t, err, ErrAlgorithmIncomplete)
}

func TestNSEC3OwnerHashErrors(t *testing.T) {
	t.Parallel()
	// Owner whose first label is invalid base32hex returns an error.
	bad := wire.MustParseName("zzzz!!.example.")
	_, err := nsec3OwnerHash(bad)
	// Surfaces the validatorbb base32hex-decode error.
	require.ErrorContains(t, err, "base32hex")
}

func TestExtractNSEC3ParamsNoNSEC3(t *testing.T) {
	t.Parallel()
	_, ok := extractNSEC3Params(nil)
	require.False(t, ok)
}

func TestExchangerSourceCounterOverflow(t *testing.T) {
	t.Parallel()
	// Drive nextID directly through the wrap branch. After the underlying
	// uint32 hits 0xFFFF, the next Add wraps the low 16 bits to zero, which
	// nextID re-advances to 1.
	s := &exchangerSource{}
	s.counter.Store(0xFFFF)
	id := s.nextID()
	require.Equal(t, uint16(1), id, "wrap should skip zero and resume at 1")
}

func TestNSEC3MatchAndCoverNotFound(t *testing.T) {
	t.Parallel()
	params := nsec3Params{alg: 1, iterations: 0, salt: nil}
	// Empty records → nothing matches/covers.
	_, ok := nsec3Match(wire.MustParseName("foo.example."), params, nil)
	require.False(t, ok)
	_, ok = nsec3Cover(wire.MustParseName("foo.example."), params, nil)
	require.False(t, ok)
}

func TestNSEC3MatchHashTooManyIterations(t *testing.T) {
	t.Parallel()
	params := nsec3Params{alg: 1, iterations: MaxNSEC3Iterations + 1, salt: nil}
	_, ok := nsec3Match(wire.MustParseName("foo.example."), params, nil)
	require.False(t, ok)
	_, ok = nsec3Cover(wire.MustParseName("foo.example."), params, nil)
	require.False(t, ok)
}

// makeNSEC3Record fabricates an NSEC3 record with a synthetic owner hash.
func makeNSEC3Record(t *testing.T, hash, next []byte, types []rrtype.Type, flags uint8) wire.Record {
	t.Helper()
	label := validatorbb.Base32HexEncode(hash)
	owner, err := wire.NameFromLabels(label, "example")
	require.NoError(t, err)
	return wire.NewRecord(owner, time.Hour, rdata.MustNewNSEC3(1, flags, 0, nil, next, types))
}

func TestNSEC3MatchSkipsNonNSEC3(t *testing.T) {
	t.Parallel()
	// Records that are not NSEC3 are ignored.
	a := wire.NewRecord(wire.MustParseName("x.example."), time.Hour,
		rdata.MustNewNS(wire.MustParseName("ns.example.")))
	params := nsec3Params{alg: 1, iterations: 0, salt: nil}
	_, ok := nsec3Match(wire.MustParseName("foo.example."), params, []wire.Record{a})
	require.False(t, ok)
	_, ok = nsec3Cover(wire.MustParseName("foo.example."), params, []wire.Record{a})
	require.False(t, ok)
}

func TestNSEC3MatchSucceeds(t *testing.T) {
	t.Parallel()
	params := nsec3Params{alg: 1, iterations: 0, salt: nil}
	target := wire.MustParseName("present.example.")
	hash := nsec3Hash(target, params.salt, params.iterations)
	rec := makeNSEC3Record(t, hash, hash, []rrtype.Type{rrtype.A}, 0)
	n3, ok := nsec3Match(target, params, []wire.Record{rec})
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
	_, ok := nsec3Cover(target, params, []wire.Record{rec})
	require.True(t, ok)
}

func TestNSEC3OwnerHashEmptyName(t *testing.T) {
	t.Parallel()
	// Root name has no labels → returns the no-label error path.
	_, err := nsec3OwnerHash(wire.RootName())
	require.ErrorContains(t, err, "no label")
}

func TestExtractNSEC3ParamsMismatch(t *testing.T) {
	t.Parallel()
	// Two NSEC3s with different iterations/salt → params disagree.
	r1 := wire.NewRecord(wire.MustParseName("aaa.example."), time.Hour,
		rdata.MustNewNSEC3(1, 0, 5, []byte{1}, make([]byte, 20), nil))
	r2 := wire.NewRecord(wire.MustParseName("bbb.example."), time.Hour,
		rdata.MustNewNSEC3(1, 0, 10, []byte{1}, make([]byte, 20), nil))
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
		rdata.MustNewNSEC3(1, 0, MaxNSEC3Iterations+1, nil, make([]byte, 20), nil))
	res := nsec3ProveDenial(wire.MustParseName("foo.example."), rrtype.A,
		wire.MustParseName("example."), []wire.Record{r})
	// RFC 9276 §3.2: a high iteration count is reported as an
	// Insecure-via-iterations signal so the walker can downgrade
	// rather than declare Bogus.
	require.Equal(t, nsec3DenialIterationsExceeded, res.kind)
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

func TestExchangerSourceLookupBuildErrorPathUnreachable(t *testing.T) {
	t.Parallel()
	// The build-error path inside Lookup is effectively unreachable with
	// a valid wire.Question — but we can still drive the success path
	// through with various option combinations to cover the remainder.
	qname := wire.MustParseName("foo.example.")
	resp, _ := wire.NewMessageBuilder().ID(1).Response(true).
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

// makeNSEC3RecordAt fabricates an NSEC3 record whose owner uses suffix as
// the zone apex labels.
func makeNSEC3RecordAt(t *testing.T, hash, next []byte, types []rrtype.Type, flags uint8, suffix ...string) wire.Record {
	t.Helper()
	label := validatorbb.Base32HexEncode(hash)
	owner, err := wire.NameFromLabels(append([]string{label}, suffix...)...)
	require.NoError(t, err)
	return wire.NewRecord(owner, time.Hour, rdata.MustNewNSEC3(1, flags, 0, nil, next, types))
}

// TestFindNSEC3ClosestEncloserMatchAtZoneApex covers the zone-equal branch
// where the NSEC3 matching the zone apex is what terminates the walk.
func TestFindNSEC3ClosestEncloserMatchAtZoneApex(t *testing.T) {
	t.Parallel()
	params := nsec3Params{alg: 1, iterations: 0, salt: nil}
	zone := wire.MustParseName("example.")
	zoneHash := nsec3Hash(zone, params.salt, params.iterations)
	rec := makeNSEC3RecordAt(t, zoneHash, zoneHash, []rrtype.Type{rrtype.SOA}, 0, "example")
	enc, ok := findNSEC3ClosestEncloser(
		wire.MustParseName("missing.example."),
		zone, params, []wire.Record{rec},
	)
	require.True(t, ok)
	require.True(t, enc.Equal(zone))
}

// TestNSEC3ProveDenialNXDomainProof drives the NXDOMAIN closest-encloser
// proof: matching NSEC3 at encloser, covering NSEC3 at next-closer, covering
// NSEC3 at *.encloser.
func TestNSEC3ProveDenialNXDomainProof(t *testing.T) {
	t.Parallel()
	params := nsec3Params{alg: 1, iterations: 0, salt: nil}
	zone := wire.MustParseName("example.")
	qname := wire.MustParseName("missing.example.")

	// Encloser match: NSEC3 owner == H(example.)
	encHash := nsec3Hash(zone, params.salt, params.iterations)
	encRec := makeNSEC3RecordAt(t, encHash, encHash, []rrtype.Type{rrtype.SOA}, 0, "example")

	// Next-closer cover: H(missing.example.) bracketed by lo,hi.
	ncHash := nsec3Hash(qname, params.salt, params.iterations)
	lo := append([]byte(nil), ncHash...)
	hi := append([]byte(nil), ncHash...)
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
	ncRec := makeNSEC3RecordAt(t, lo, hi, nil, 0, "example")

	// Wildcard cover: cover H(*.example.).
	wc, err := validatorbb.WildcardOf(zone)
	require.NoError(t, err)
	wcHash := nsec3Hash(wc, params.salt, params.iterations)
	wlo := append([]byte(nil), wcHash...)
	whi := append([]byte(nil), wcHash...)
	for i := len(wlo) - 1; i >= 0; i-- {
		if wlo[i] > 0 {
			wlo[i]--
			break
		}
		wlo[i] = 0xff
	}
	for i := len(whi) - 1; i >= 0; i-- {
		if whi[i] < 0xff {
			whi[i]++
			break
		}
		whi[i] = 0
	}
	wcRec := makeNSEC3RecordAt(t, wlo, whi, nil, 0, "example")

	res := nsec3ProveDenial(qname, rrtype.A, zone, []wire.Record{encRec, ncRec, wcRec})
	require.Equal(t, nsec3DenialNXDomain, res.kind)
	require.True(t, res.closestEncloser.Equal(zone))
}

// TestNSEC3ProveDenialNoEncloser drives step 3 of nsec3ProveDenial when
// findNSEC3ClosestEncloser fails (records present but none match an
// ancestor of qname).
func TestNSEC3ProveDenialNoEncloser(t *testing.T) {
	t.Parallel()
	// One NSEC3 with a deliberately unrelated owner-hash so no parent of
	// qname matches.
	rec := wire.NewRecord(wire.MustParseName("0.example."), time.Hour,
		rdata.MustNewNSEC3(1, 0, 0, nil, make([]byte, 20), []rrtype.Type{rrtype.A}))
	res := nsec3ProveDenial(
		wire.MustParseName("missing.example."),
		rrtype.AAAA,
		wire.MustParseName("example."),
		[]wire.Record{rec},
	)
	require.Equal(t, nsec3DenialNone, res.kind)
}

// TestExtractNSEC3ParamsFirstWins verifies the first-record-wins path of
// extractNSEC3Params (single-NSEC3 fast path).
func TestExtractNSEC3ParamsFirstWins(t *testing.T) {
	t.Parallel()
	r1 := wire.NewRecord(wire.MustParseName("aaa.example."), time.Hour,
		rdata.MustNewNSEC3(1, 0, 5, []byte{1, 2, 3}, make([]byte, 20), nil))
	got, ok := extractNSEC3Params([]wire.Record{r1})
	require.True(t, ok)
	require.Equal(t, uint16(5), got.iterations)
	require.Equal(t, []byte{1, 2, 3}, got.salt)
}
