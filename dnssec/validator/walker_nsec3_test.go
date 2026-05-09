package validator_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnssec/validator"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// buildNSEC3Chain mirrors buildChain but routes denial-of-existence proofs
// through NSEC3.
func buildNSEC3Chain(t *testing.T, alg rdata.DNSSECAlgorithm, mode nsec3Mode, now time.Time) (*nsec3Source, validator.Walker, validator.Anchor) {
	t.Helper()
	root := newSignedZone(t, wire.RootName(), alg, now)
	tld := newSignedZone(t, wire.MustParseName("example."), alg, now)
	leaf := newSignedZone(t, wire.MustParseName("sub.example."), alg, now)

	leaf.addRR(wire.NewRecord(wire.MustParseName("www.sub.example."), time.Hour,
		rdata.MustNewA(netip.MustParseAddr("192.0.2.1"))))

	root.publishDNSKEY()
	tld.publishDNSKEY()
	leaf.publishDNSKEY()
	root.addDelegation(t, tld)
	tld.addDelegation(t, leaf)

	src := newNSEC3Source(mode, root, tld, leaf)
	rootAnchor, err := root.rootAnchor(t)
	require.NoError(t, err)
	anchor, err := validator.NewAnchor(rootAnchor.apex, rootAnchor.ds)
	require.NoError(t, err)

	w, err := validator.NewWalker(src,
		validator.WithWalkerAnchors(anchor),
		validator.WithWalkerNow(func() time.Time { return now }),
	)
	require.NoError(t, err)
	return src, w, anchor
}

func TestWalkerNSEC3Secure(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	mode := nsec3Mode{iterations: 0, salt: []byte{0xab, 0xcd}}
	_, w, _ := buildNSEC3Chain(t, rdata.AlgECDSAP256SHA256, mode, now)
	ans, err := w.Resolve(t.Context(), wire.MustParseName("www.sub.example."), rrtype.A)
	require.NoError(t, err)
	require.Equal(t, validator.Secure, ans.Result(), "reason: %v", ans.Reason())
}

func TestWalkerNSEC3NXDOMAIN(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	mode := nsec3Mode{iterations: 0, salt: []byte{0xab, 0xcd}}
	_, w, _ := buildNSEC3Chain(t, rdata.AlgECDSAP256SHA256, mode, now)
	ans, err := w.Resolve(t.Context(), wire.MustParseName("missing.sub.example."), rrtype.A)
	require.NoError(t, err, "reason: %v", func() error {
		if ans != nil {
			return ans.Reason()
		}
		return nil
	}())
	require.Equal(t, validator.Secure, ans.Result(), "reason: %v", ans.Reason())
	require.Equal(t, wire.RCODENXDomain, ans.RCODE())
}

func TestWalkerNSEC3OptOutInsecure(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	mode := nsec3Mode{iterations: 0, salt: []byte{0xab, 0xcd}, optOut: true}
	root := newSignedZone(t, wire.RootName(), rdata.AlgECDSAP256SHA256, now)
	tld := newSignedZone(t, wire.MustParseName("example."), rdata.AlgECDSAP256SHA256, now)
	root.publishDNSKEY()
	tld.publishDNSKEY()
	root.addDelegation(t, tld)
	// Add an unsigned NS delegation. With opt-out, the parent has NO DS
	// record but the name exists (NS record present). DS lookup → NoData
	// covered by opt-out NSEC3 → Insecure.
	tld.addRR(wire.NewRecord(wire.MustParseName("insecure.example."), time.Hour,
		rdata.NewNS(wire.MustParseName("ns.insecure.example."))))

	src := newNSEC3Source(mode, root, tld)
	rootDS, _ := root.rootAnchor(t)
	anchor, _ := validator.NewAnchor(rootDS.apex, rootDS.ds)
	w, err := validator.NewWalker(src,
		validator.WithWalkerAnchors(anchor),
		validator.WithWalkerNow(func() time.Time { return now }),
	)
	require.NoError(t, err)
	ans, err := w.Resolve(t.Context(), wire.MustParseName("ns.insecure.example."), rrtype.A)
	require.NoError(t, err, "reason: %v", ans.Reason())
	require.Equal(t, validator.Insecure, ans.Result(), "reason: %v", ans.Reason())
}

func TestWalkerNSEC3IterationCap(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	// Iterations above the cap should refuse to validate denial → Bogus.
	mode := nsec3Mode{iterations: validator.MaxNSEC3Iterations + 1, salt: []byte{0xab, 0xcd}}
	_, w, _ := buildNSEC3Chain(t, rdata.AlgECDSAP256SHA256, mode, now)
	wBogus, err := validator.NewWalker(
		newNSEC3SourceFrom(t, mode, rdata.AlgECDSAP256SHA256, now),
		validator.WithWalkerAnchors(newRootAnchor(t, rdata.AlgECDSAP256SHA256, now)),
		validator.WithWalkerNow(func() time.Time { return now }),
		validator.WithWalkerBogusPolicy(validator.BogusReturnAnswer),
	)
	require.NoError(t, err)
	_ = w
	ans, err := wBogus.Resolve(t.Context(), wire.MustParseName("missing.sub.example."), rrtype.A)
	require.NoError(t, err)
	require.Equal(t, validator.Bogus, ans.Result())
}

// newNSEC3SourceFrom builds a fresh NSEC3-mode source with the requested
// algorithm — used for tests that need an independent walker.
func newNSEC3SourceFrom(t *testing.T, mode nsec3Mode, alg rdata.DNSSECAlgorithm, now time.Time) *nsec3Source {
	t.Helper()
	root := newSignedZone(t, wire.RootName(), alg, now)
	tld := newSignedZone(t, wire.MustParseName("example."), alg, now)
	leaf := newSignedZone(t, wire.MustParseName("sub.example."), alg, now)
	leaf.addRR(wire.NewRecord(wire.MustParseName("www.sub.example."), time.Hour,
		rdata.MustNewA(netip.MustParseAddr("192.0.2.1"))))
	root.publishDNSKEY()
	tld.publishDNSKEY()
	leaf.publishDNSKEY()
	root.addDelegation(t, tld)
	tld.addDelegation(t, leaf)
	return newNSEC3Source(mode, root, tld, leaf)
}

func newRootAnchor(t *testing.T, alg rdata.DNSSECAlgorithm, now time.Time) validator.Anchor {
	t.Helper()
	root := newSignedZone(t, wire.RootName(), alg, now)
	rootDS, err := root.rootAnchor(t)
	require.NoError(t, err)
	a, err := validator.NewAnchor(rootDS.apex, rootDS.ds)
	require.NoError(t, err)
	return a
}
