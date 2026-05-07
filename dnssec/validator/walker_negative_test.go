package validator_test

import (
	"context"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnssec/validator"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// rcodeRewriter wraps a Source so that any NoError NoData response for the
// configured (qname, qtype) is reissued with RCODENXDomain. The signed NSEC
// authority is preserved verbatim — the NSEC's owner equals qname, which
// proves NoData but does NOT cover qname for an NXDOMAIN proof. This drives
// validateNegative through its NXDOMAIN branch into validateNXDomain →
// bogus.
type rcodeRewriter struct {
	inner  validator.Source
	target wire.Name
	qtype  rrtype.Type
}

func (s *rcodeRewriter) Lookup(ctx context.Context, qname wire.Name, qtype rrtype.Type) (wire.Message, error) {
	m, err := s.inner.Lookup(ctx, qname, qtype)
	if err != nil {
		return nil, err
	}
	if !qname.Equal(s.target) || qtype != s.qtype {
		return m, nil
	}
	if m.Flags().RCODE() != wire.RCODENoError || len(m.Answers()) > 0 {
		return m, nil
	}
	b := wire.NewBuilder().
		ID(m.ID()).
		Response(true).
		RCODE(wire.RCODENXDomain).
		Question(wire.NewQuestion(qname, qtype))
	for _, a := range m.Authorities() {
		b.Authority(a)
	}
	return b.Build()
}

// TestWalkerValidateNegativeNXDOMAINBogus drives validateNegative's NXDOMAIN
// branch when the upstream lies (NoData → RCODENXDomain) and the supplied
// NSEC fails to cover qname. Walker must classify Bogus.
func TestWalkerValidateNegativeNXDOMAINBogus(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	src, _, anchor := buildChain(t, rdata.AlgECDSAP256SHA256, now)

	target := wire.MustParseName("sub.example.")
	wrapped := &rcodeRewriter{inner: src, target: target, qtype: rrtype.AAAA}

	w, err := validator.NewWalker(wrapped,
		validator.WithAnchors(anchor),
		validator.WithNow(func() time.Time { return now }),
		validator.WithBogusPolicy(validator.BogusReturnAnswer),
	)
	require.NoError(t, err)
	ans, err := w.Resolve(t.Context(), target, rrtype.AAAA)
	require.NoError(t, err)
	require.Equal(t, validator.Bogus, ans.Result())
	require.Error(t, ans.Reason())
}

// nxdomainForger wraps a Source so that for the configured (qname, qtype),
// the response is rebuilt as RCODENXDomain with a freshly-synthesised
// covering NSEC signed by the zone's keys. This drives validateNegative
// through the secure NXDOMAIN branch.
type nxdomainForger struct {
	inner   validator.Source
	zone    *signedZone
	target  wire.Name
	qtype   rrtype.Type
	owner   wire.Name
	next    wire.Name
}

func (s *nxdomainForger) Lookup(ctx context.Context, qname wire.Name, qtype rrtype.Type) (wire.Message, error) {
	m, err := s.inner.Lookup(ctx, qname, qtype)
	if err != nil {
		return nil, err
	}
	if !qname.Equal(s.target) || qtype != s.qtype {
		return m, nil
	}
	// Build a covering NSEC at s.owner whose next field is s.next, signed
	// by the leaf zone. The validator's NameCoveredBy check accepts this
	// because s.owner < s.target < s.next in canonical order.
	nsec := rdata.NewNSEC(s.next, []rrtype.Type{rrtype.A, rrtype.NSEC, rrtype.RRSIG})
	rec := wire.NewRecord(s.owner, time.Hour, nsec)
	sig := s.zone.signRRset([]wire.Record{rec})
	return wire.NewBuilder().
		ID(m.ID()).
		Response(true).
		RCODE(wire.RCODENXDomain).
		Question(wire.NewQuestion(qname, qtype)).
		Authority(rec).
		Authority(wire.NewRecord(s.owner, time.Hour, sig)).
		Build()
}

// findLeafZone digs into a fixtureSource for the deepest zone matching apex.
func findLeafZone(src *fixtureSource, apex wire.Name) *signedZone {
	for _, z := range src.zones {
		if z.apex.Equal(apex) {
			return z
		}
	}
	return nil
}

// TestWalkerValidateNegativeNXDOMAINSecure drives validateNegative's NXDOMAIN
// success path. The synthetic NSEC owned by "a.sub.example." with next
// "z.sub.example." canonically covers qname "m.sub.example.", and the leaf
// zone's keys validly sign it.
func TestWalkerValidateNegativeNXDOMAINSecure(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	src, _, anchor := buildChain(t, rdata.AlgECDSAP256SHA256, now)
	leaf := findLeafZone(src, wire.MustParseName("sub.example."))
	require.NotNil(t, leaf)

	// We need a target that:
	//   - is a zone apex (so walkChain returns zone.Equal(qname) at line
	//     254 without consulting any DS at the target itself), so that
	//     validateNegative is reached on an RCODENXDomain answer; AND
	//   - is canonically covered by the synthetic NSEC pair.
	//
	// "sub.example." is the leaf apex. Canonical-form ordering of suffixes
	// is root-first; "a.sub.example." sorts strictly before "sub.example."
	// as long as we give it a label longer than empty. Likewise
	// "z.sub.example." sorts strictly after.  Construct NSEC owned by
	// "a.sub.example." with next "z.sub.example.".
	// In RFC 4034 §6.1 canonical ordering "s.example." sorts before
	// "sub.example." (shorter label prefix), and "tub.example." sorts after
	// (different first byte: 't' > 's'). The NSEC pair therefore strictly
	// covers the target.
	target := wire.MustParseName("sub.example.")
	owner := wire.MustParseName("s.example.")
	next := wire.MustParseName("tub.example.")

	wrapped := &nxdomainForger{
		inner:  src,
		zone:   leaf,
		target: target,
		qtype:  rrtype.AAAA,
		owner:  owner,
		next:   next,
	}

	w, err := validator.NewWalker(wrapped,
		validator.WithAnchors(anchor),
		validator.WithNow(func() time.Time { return now }),
	)
	require.NoError(t, err)
	ans, err := w.Resolve(t.Context(), target, rrtype.AAAA)
	require.NoError(t, err, "reason: %v", func() error {
		if ans != nil {
			return ans.Reason()
		}
		return nil
	}())
	require.Equal(t, validator.Secure, ans.Result(), "reason: %v", ans.Reason())
	require.Equal(t, wire.RCODENXDomain, ans.RCODE())
}

// nodataSigStripper wraps a Source so that the configured (qname, qtype)
// NoData response loses its RRSIG covering the NSEC authority — driving
// validateNoDataNSEC's "no sigs" early-return (line 612-613), which then
// falls through to NSEC3 (no NSEC3 → false) and ends in bogus.
type nodataSigStripper struct {
	inner  validator.Source
	target wire.Name
	qtype  rrtype.Type
}

func (s *nodataSigStripper) Lookup(ctx context.Context, qname wire.Name, qtype rrtype.Type) (wire.Message, error) {
	m, err := s.inner.Lookup(ctx, qname, qtype)
	if err != nil {
		return nil, err
	}
	if !qname.Equal(s.target) || qtype != s.qtype {
		return m, nil
	}
	if m.Flags().RCODE() != wire.RCODENoError || len(m.Answers()) > 0 {
		return m, nil
	}
	b := wire.NewBuilder().
		ID(m.ID()).
		Response(true).
		RCODE(m.Flags().RCODE()).
		Question(wire.NewQuestion(qname, qtype))
	// Drop RRSIG records from authority; keep the NSEC.
	for _, a := range m.Authorities() {
		if a.Type() == rrtype.RRSIG {
			continue
		}
		b.Authority(a)
	}
	return b.Build()
}

// TestWalkerValidateNoDataNSECNoSigs drives validateNoDataNSEC's early
// return when no RRSIG is present over the NSEC. Falls through to NSEC3
// (none) and ends in bogus.
func TestWalkerValidateNoDataNSECNoSigs(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	src, _, anchor := buildChain(t, rdata.AlgECDSAP256SHA256, now)
	target := wire.MustParseName("sub.example.")
	wrapped := &nodataSigStripper{inner: src, target: target, qtype: rrtype.AAAA}

	w, err := validator.NewWalker(wrapped,
		validator.WithAnchors(anchor),
		validator.WithNow(func() time.Time { return now }),
		validator.WithBogusPolicy(validator.BogusReturnAnswer),
	)
	require.NoError(t, err)
	ans, err := w.Resolve(t.Context(), target, rrtype.AAAA)
	require.NoError(t, err)
	require.Equal(t, validator.Bogus, ans.Result())
	require.Error(t, ans.Reason())
}
