package validator_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnssec"
	"github.com/lestrrat-go/acidns/dnssec/validator"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// extraSigPrepender wraps a Source so the answer for (target, qtype) carries
// N-1 invalid RRSIGs prepended in front of the legitimate one — exercising
// the regression that pre-truncated the sig slice and dropped the only
// valid RRSIG when it sorted last.
type extraSigPrepender struct {
	inner  validator.Source
	target wire.Name
	qtype  rrtype.Type
	extras int
}

func (s *extraSigPrepender) Lookup(ctx context.Context, qname wire.Name, qtype rrtype.Type) (wire.Message, error) {
	m, err := s.inner.Lookup(ctx, qname, qtype)
	if err != nil {
		return wire.Message{}, err
	}
	if !qname.Equal(s.target) || qtype != s.qtype {
		return m, nil
	}
	// Find the legitimate RRSIG covering qtype, then rebuild answers with
	// `extras` bogus RRSIGs of the same algorithm prepended ahead of it.
	var legitSig wire.Record
	var legitRRSIG rdata.RRSIG
	var legitFound bool
	var others []wire.Record
	for _, a := range m.Answers() {
		if a.Type() == rrtype.RRSIG {
			rrsig, ok := wire.RDataAs[rdata.RRSIG](a)
			if ok && rrsig.TypeCovered() == qtype && !legitFound {
				legitSig = a
				legitRRSIG = rrsig
				legitFound = true
				continue
			}
		}
		others = append(others, a)
	}
	if !legitFound {
		return m, nil
	}
	b := wire.NewMessageBuilder().
		ID(m.ID()).
		Response(true).
		RCODE(m.Flags().RCODE()).
		Question(wire.NewQuestion(qname, qtype))
	for _, a := range others {
		b.Answer(a)
	}
	// Prepend `extras` bogus RRSIGs that share the legit sig's algorithm
	// and KeyTag — they will match a key but Verify will fail. The only
	// valid sig sits at position `extras` (i.e. last among the RRSIGs).
	for i := 0; i < s.extras; i++ {
		bogus := rdata.NewRRSIG(
			legitRRSIG.TypeCovered(), legitRRSIG.Algorithm(),
			legitRRSIG.Labels(), legitRRSIG.OriginalTTL(),
			legitRRSIG.SignatureExpiration(), legitRRSIG.SignatureInception(),
			legitRRSIG.KeyTag(), legitRRSIG.SignerName(), make([]byte, 64),
		)
		b.Answer(wire.NewRecord(legitSig.Name(), legitSig.TTL(), bogus))
	}
	b.Answer(legitSig)
	return b.Build()
}

// Fix 1 regression: with N RRSIGs where the only valid sig is last,
// verifyRRsetWithKeys (via the answer path's verifyRRsetAllAlgs which
// short-circuits to verifyRRsetWithKeys when no DS algs are tracked, and
// internal callers like DNSKEY/DS/NSEC) must still succeed because the cap
// applies to attempted Verify calls, not by slice truncation.
//
// We exercise the answer path with a single algorithm — verifyRRsetAllAlgs
// will iterate each sig and the cap on attempted Verify calls is enforced
// only on candidate (matching key+alg) pairs. With four bogus sigs (each
// driving one Verify) the budget of 5 still admits the fifth (legit) sig.
func TestWalkerFix1ValidSigLastNotTruncated(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	src, _, anchor := buildChain(t, rdata.AlgECDSAP256SHA256, now)
	target := wire.MustParseName("www.sub.example.")
	wrapped := &extraSigPrepender{inner: src, target: target, qtype: rrtype.A, extras: 4}
	w, err := validator.NewWalker(wrapped,
		validator.WithWalkerAnchors(anchor),
		validator.WithWalkerClock(func() time.Time { return now }),
		validator.WithWalkerMaxRRSIGsTry(5),
	)
	require.NoError(t, err)
	ans, err := w.Resolve(t.Context(), target, rrtype.A)
	require.NoError(t, err, "reason: %v", ans.Reason())
	require.Equal(t, validator.Secure, ans.Result(), "reason: %v", ans.Reason())
}

// Fix 2 regression: bogus reasons must wrap ErrBogus while still preserving
// the underlying error chain so callers can errors.Is on the concrete cause.
func TestWalkerFix2BogusWrapsErrBogus(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	t.Run("expired RRSIG", func(t *testing.T) {
		src, _, anchor := buildChain(t, rdata.AlgECDSAP256SHA256, now)
		w, err := validator.NewWalker(src,
			validator.WithWalkerAnchors(anchor),
			validator.WithWalkerClock(func() time.Time { return now.Add(48 * time.Hour) }),
			validator.WithWalkerBogusPolicy(validator.BogusReturnAnswer),
		)
		require.NoError(t, err)
		ans, err := w.Resolve(t.Context(), wire.MustParseName("www.sub.example."), rrtype.A)
		require.NoError(t, err)
		require.Equal(t, validator.Bogus, ans.Result())
		require.ErrorIs(t, ans.Reason(), validator.ErrBogus)
	})
	t.Run("unsigned answer", func(t *testing.T) {
		src, _, anchor := buildChain(t, rdata.AlgECDSAP256SHA256, now)
		wrapped := &sigStripper{
			inner:  src,
			target: wire.MustParseName("www.sub.example."),
			qtype:  rrtype.A,
		}
		w, err := validator.NewWalker(wrapped,
			validator.WithWalkerAnchors(anchor),
			validator.WithWalkerClock(func() time.Time { return now }),
			validator.WithWalkerBogusPolicy(validator.BogusReturnAnswer),
		)
		require.NoError(t, err)
		ans, err := w.Resolve(t.Context(), wire.MustParseName("www.sub.example."), rrtype.A)
		require.NoError(t, err)
		require.Equal(t, validator.Bogus, ans.Result())
		require.ErrorIs(t, ans.Reason(), validator.ErrBogus)
		require.ErrorIs(t, ans.Reason(), validator.ErrUnsignedAnswer)
	})
}

// Fix 3 regression: an unconfigured Walker (no anchors) returns
// ErrNoTrustAnchor instead of silently using the embedded IANA root.
func TestWalkerFix3NoAnchorsReturnsErrNoTrustAnchor(t *testing.T) {
	t.Parallel()
	src := newFixtureSource()
	w, err := validator.NewWalker(src)
	require.NoError(t, err)
	ans, err := w.Resolve(t.Context(), wire.MustParseName("example.com."), rrtype.A)
	require.ErrorIs(t, err, validator.ErrNoTrustAnchor)
	require.Equal(t, validator.Indeterminate, ans.Result())
}

// Fix 3: WithWalkerIANARootAnchor explicitly opts the caller into the
// embedded anchor. The walker then treats queries under the root as
// covered (and proceeds to fail the chain walk because the fixture source
// is empty — but the anchor selection succeeds, which is what we test).
func TestWalkerFix3IANARootAnchorOptInExposesAnchor(t *testing.T) {
	t.Parallel()
	src := newFixtureSource()
	w, err := validator.NewWalker(src,
		validator.WithWalkerIANARootAnchor(true),
		validator.WithWalkerBogusPolicy(validator.BogusReturnAnswer),
	)
	require.NoError(t, err)
	ans, err := w.Resolve(t.Context(), wire.MustParseName("example.com."), rrtype.A)
	require.NoError(t, err)
	// With the empty fixture source we can't fetch DNSKEY; result is bogus
	// but importantly NOT ErrNoTrustAnchor — the anchor IS configured.
	require.NotEqual(t, validator.Indeterminate, ans.Result())
}

// Fix 4 regression: Validator.ValidateRRset honours WithValidatorClockSkew.
func TestValidatorFix4SkewTolerance(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	encPK, err := priv.PublicKey.Bytes()
	require.NoError(t, err)
	key := rdata.NewDNSKEY(257, 3, rdata.AlgECDSAP256SHA256, encPK[1:])

	now := time.Now().UTC().Truncate(time.Second)
	set := []wire.Record{
		wire.NewRecord(wire.MustParseName("example.com"), time.Hour,
			rdata.MustNewA(netip.MustParseAddr("192.0.2.1"))),
	}
	// Inception 30s in the future — without skew, this is outside the window.
	inception := now.Add(30 * time.Second)
	expiration := now.Add(time.Hour)
	skeleton := rdata.NewRRSIG(set[0].Type(), rdata.AlgECDSAP256SHA256,
		uint8(set[0].Name().NumLabels()), set[0].TTL(),
		expiration, inception, dnssec.KeyTag(key), set[0].Name(), nil)
	payload, err := dnssec.SignedData(set, skeleton)
	require.NoError(t, err)
	hashed := sha256.Sum256(payload)
	r, s, err := ecdsa.Sign(rand.Reader, priv, hashed[:])
	require.NoError(t, err)
	sigBytes := make([]byte, 64)
	r.FillBytes(sigBytes[:32])
	s.FillBytes(sigBytes[32:])
	sig := rdata.NewRRSIG(set[0].Type(), rdata.AlgECDSAP256SHA256,
		uint8(set[0].Name().NumLabels()), set[0].TTL(),
		expiration, inception, dnssec.KeyTag(key), set[0].Name(), sigBytes)

	t.Run("skew=0 rejects future inception", func(t *testing.T) {
		v, err := validator.New(
			validator.WithValidatorClock(func() time.Time { return now }),
			validator.WithValidatorBogusPolicy(validator.BogusReturnAnswer),
		)
		require.NoError(t, err)
		res, _, err := v.ValidateRRset(set, []rdata.RRSIG{sig}, []rdata.DNSKEY{key})
		require.Error(t, err)
		require.Equal(t, validator.Bogus, res)
	})
	t.Run("skew=1m accepts future inception", func(t *testing.T) {
		v, err := validator.New(
			validator.WithValidatorClock(func() time.Time { return now }),
			validator.WithValidatorClockSkew(time.Minute),
		)
		require.NoError(t, err)
		res, _, err := v.ValidateRRset(set, []rdata.RRSIG{sig}, []rdata.DNSKEY{key})
		require.NoError(t, err)
		require.Equal(t, validator.Secure, res)
	})
}
