package validator_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnssec/validator"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// buildChain spins up three zones — root → example → www.example — all
// signed with the requested algorithm and returns the fixture source plus
// a walker anchored at the root's KSK.
func buildChain(t *testing.T, alg rdata.DNSSECAlgorithm, now time.Time) (*fixtureSource, validator.Walker, validator.Anchor) {
	t.Helper()
	root := newSignedZone(t, wire.RootName(), alg, now)
	tld := newSignedZone(t, wire.MustParseName("example."), alg, now)
	leaf := newSignedZone(t, wire.MustParseName("sub.example."), alg, now)

	// Add data records.
	leaf.addRR(wire.NewRecord(wire.MustParseName("www.sub.example."), time.Hour,
		rdata.NewA(netip.MustParseAddr("192.0.2.1"))))

	// Publish DNSKEYs at each apex and wire up delegations.
	root.publishDNSKEY()
	tld.publishDNSKEY()
	leaf.publishDNSKEY()
	root.addDelegation(t, tld)
	tld.addDelegation(t, leaf)

	src := newFixtureSource(root, tld, leaf)

	rootAnchor, err := root.rootAnchor(t)
	require.NoError(t, err)
	anchor, err := validator.NewAnchor(rootAnchor.apex, rootAnchor.ds)
	require.NoError(t, err)

	w, err := validator.NewWalker(src,
		validator.WithAnchors(anchor),
		validator.WithNow(func() time.Time { return now }),
	)
	require.NoError(t, err)
	return src, w, anchor
}

func TestWalkerSecureECDSA(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	_, w, _ := buildChain(t, rdata.AlgECDSAP256SHA256, now)
	ans, err := w.Resolve(t.Context(), wire.MustParseName("www.sub.example."), rrtype.A)
	require.NoError(t, err)
	require.Equal(t, validator.Secure, ans.Result(), "reason: %v", ans.Reason())
	require.Len(t, ans.Records(), 1)
	require.Equal(t, rrtype.A, ans.Records()[0].Type())
	// Chain: root + example + sub.example.
	require.Len(t, ans.Chain(), 3)
}

func TestWalkerSecureED25519(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	_, w, _ := buildChain(t, rdata.AlgED25519, now)
	ans, err := w.Resolve(t.Context(), wire.MustParseName("www.sub.example."), rrtype.A)
	require.NoError(t, err)
	require.Equal(t, validator.Secure, ans.Result(), "reason: %v", ans.Reason())
}

func TestWalkerSecureECDSAP384(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	_, w, _ := buildChain(t, rdata.AlgECDSAP384SHA384, now)
	ans, err := w.Resolve(t.Context(), wire.MustParseName("www.sub.example."), rrtype.A)
	require.NoError(t, err)
	require.Equal(t, validator.Secure, ans.Result(), "reason: %v", ans.Reason())
}

func TestWalkerNTAShortCircuit(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	root := newSignedZone(t, wire.RootName(), rdata.AlgECDSAP256SHA256, now)
	root.publishDNSKEY()
	src := newFixtureSource(root)
	rootDS, err := root.rootAnchor(t)
	require.NoError(t, err)
	anchor, _ := validator.NewAnchor(rootDS.apex, rootDS.ds)

	store := validator.NewNTAStore(wire.MustParseName("naughty.example."))
	w, err := validator.NewWalker(src,
		validator.WithAnchors(anchor),
		validator.WithNTAStore(store),
		validator.WithNow(func() time.Time { return now }),
	)
	require.NoError(t, err)

	ans, err := w.Resolve(t.Context(), wire.MustParseName("naughty.example."), rrtype.A)
	require.NoError(t, err)
	require.Equal(t, validator.Indeterminate, ans.Result())
}

func TestWalkerNoTrustAnchor(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	src := newFixtureSource()
	otherAnchor, err := validator.NewAnchor(wire.MustParseName("other."),
		rdata.NewDS(1, rdata.AlgECDSAP256SHA256, rdata.DigestSHA256, make([]byte, 32)))
	require.NoError(t, err)
	w, err := validator.NewWalker(src,
		validator.WithAnchors(otherAnchor),
		validator.WithNow(func() time.Time { return now }),
	)
	require.NoError(t, err)
	ans, err := w.Resolve(t.Context(), wire.MustParseName("example.com."), rrtype.A)
	require.ErrorIs(t, err, validator.ErrNoTrustAnchor)
	require.Equal(t, validator.Indeterminate, ans.Result())
}

func TestWalkerExpiredSignatureBogus(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	src, _, anchor := buildChain(t, rdata.AlgECDSAP256SHA256, now)
	// Walker with an effective time well past signature expiration.
	wFuture, err := validator.NewWalker(src,
		validator.WithAnchors(anchor),
		validator.WithNow(func() time.Time { return now.Add(48 * time.Hour) }),
		validator.WithBogusPolicy(validator.BogusReturnAnswer),
	)
	require.NoError(t, err)
	ans, err := wFuture.Resolve(t.Context(), wire.MustParseName("www.sub.example."), rrtype.A)
	require.NoError(t, err)
	require.Equal(t, validator.Bogus, ans.Result())
}

func TestWalkerInsecureDelegation(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	root := newSignedZone(t, wire.RootName(), rdata.AlgECDSAP256SHA256, now)
	tld := newSignedZone(t, wire.MustParseName("example."), rdata.AlgECDSAP256SHA256, now)
	// Unsigned grandchild — no DS at "insecure.example.".
	root.publishDNSKEY()
	tld.publishDNSKEY()
	root.addDelegation(t, tld)
	// Add an NS record for "insecure.example." but NO DS record. The TLD's
	// NSEC at "insecure.example." should reflect: NS, RRSIG, NSEC — no DS,
	// no SOA. Our fixture source synthesises NSEC from typesAt.
	tld.addRR(wire.NewRecord(wire.MustParseName("insecure.example."), time.Hour,
		rdata.NewNS(wire.MustParseName("ns.insecure.example."))))

	src := newFixtureSource(root, tld)
	rootDS, _ := root.rootAnchor(t)
	anchor, _ := validator.NewAnchor(rootDS.apex, rootDS.ds)
	w, err := validator.NewWalker(src,
		validator.WithAnchors(anchor),
		validator.WithNow(func() time.Time { return now }),
	)
	require.NoError(t, err)

	ans, err := w.Resolve(t.Context(), wire.MustParseName("ns.insecure.example."), rrtype.A)
	require.NoError(t, err, "got reason %v", ans.Reason())
	require.Equal(t, validator.Insecure, ans.Result(), "reason: %v", ans.Reason())
}

func TestWalkerTamperedAnswerBogus(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	src, _, anchor := buildChain(t, rdata.AlgECDSAP256SHA256, now)
	// Mutate the leaf zone to flip an answer byte.
	tampered := tamperFixture(src, wire.MustParseName("www.sub.example."), rrtype.A)
	require.True(t, tampered)

	wTamper, err := validator.NewWalker(src,
		validator.WithAnchors(anchor),
		validator.WithNow(func() time.Time { return now }),
		validator.WithBogusPolicy(validator.BogusReturnAnswer),
	)
	require.NoError(t, err)
	ans, err := wTamper.Resolve(t.Context(), wire.MustParseName("www.sub.example."), rrtype.A)
	require.NoError(t, err)
	require.Equal(t, validator.Bogus, ans.Result())
	require.Error(t, ans.Reason())
}

// tamperFixture swaps the ZSK private key on whichever zone currently
// owns (name, t) so that future ZSK-signed RRSIGs over that rrset will
// fail to verify against the published DNSKEY public key. The KSK is
// untouched, so the chain walk through the DNSKEY rrset still validates.
func tamperFixture(s *fixtureSource, name wire.Name, t rrtype.Type) bool {
	for _, z := range s.zones {
		k := recKey{name: name.String(), typ: t}
		if _, ok := z.rrsets[k]; !ok {
			continue
		}
		// Replace the ZSK's private key with a freshly-generated one of
		// the same algorithm. The published DNSKEY (z.zsk.dnskey) keeps
		// the OLD public key, so signatures produced with the new private
		// key will not verify.
		switch z.zsk.alg {
		case rdata.AlgECDSAP256SHA256:
			priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				panic(err)
			}
			z.zsk.ecdsa = priv
		case rdata.AlgECDSAP384SHA384:
			priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			if err != nil {
				panic(err)
			}
			z.zsk.ecdsa = priv
		case rdata.AlgED25519:
			_, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				panic(err)
			}
			z.zsk.ed25519 = priv
		default:
			return false
		}
		return true
	}
	return false
}

func TestWalkerNXDOMAIN(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	_, w, _ := buildChain(t, rdata.AlgECDSAP256SHA256, now)
	ans, err := w.Resolve(t.Context(), wire.MustParseName("missing.sub.example."), rrtype.A)
	require.NoError(t, err, "reason: %v", func() error {
		if ans != nil {
			return ans.Reason()
		}
		return nil
	}())
	require.Equal(t, validator.Secure, ans.Result(), "reason: %v", ans.Reason())
	require.Equal(t, wire.RCODENXDomain, ans.RCODE())
	require.Empty(t, ans.Records())
}

func TestWalkerMaxZoneCutsBomb(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	src, _, anchor := buildChain(t, rdata.AlgECDSAP256SHA256, now)
	wTight, err := validator.NewWalker(src,
		validator.WithAnchors(anchor),
		validator.WithNow(func() time.Time { return now }),
		validator.WithMaxZoneCuts(1),
		validator.WithBogusPolicy(validator.BogusReturnAnswer),
	)
	require.NoError(t, err)
	ans, err := wTight.Resolve(t.Context(), wire.MustParseName("www.sub.example."), rrtype.A)
	require.NoError(t, err)
	require.Equal(t, validator.Bogus, ans.Result())
}
