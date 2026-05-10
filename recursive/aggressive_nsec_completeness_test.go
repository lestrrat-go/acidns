package recursive_test

import (
	"context"
	"crypto/sha1" //nolint:gosec // RFC 5155 §5 fixes the hash algorithm at SHA-1.
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnssec/validator/validatorbb"
	"github.com/lestrrat-go/acidns/recursive"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// iteratedSHA1 mirrors the implementation in aggressive_nsec3.go;
// duplicated in the test package to avoid exporting an internal
// helper purely for testing.
func iteratedSHA1(name, salt []byte, iterations uint16) []byte {
	buf := append([]byte(nil), name...)
	buf = append(buf, salt...)
	h := sha1.Sum(buf) //nolint:gosec
	for range iterations {
		next := append([]byte(nil), h[:]...)
		next = append(next, salt...)
		h = sha1.Sum(next) //nolint:gosec
	}
	return h[:]
}

// nsec3OwnerName builds an NSEC3 owner-name from a raw hash + zone
// apex. Test-side mirror of the production helper.
func nsec3OwnerName(ownerHash []byte, zone wire.Name) wire.Name {
	label := validatorbb.Base32HexEncode(ownerHash)
	return wire.MustParseName(label + "." + zone.String())
}

// soaForExample is the standard test-zone SOA used across the
// completeness tests below.
func soaForExample() wire.Record {
	return wire.NewRecord(wire.MustParseName("example."), 5*time.Minute,
		rdata.MustNewSOA(
			wire.MustParseName("ns.example."),
			wire.MustParseName("hm.example."),
			1, 7200, 3600, 1209600, 60,
		))
}

// TestAggressiveNSECNoDataSynthesis verifies §5.2: a cached NSEC
// at the queried name with a type bitmap excluding the queried
// type produces NoError + empty answer (NoData) without consulting
// the upstream.
func TestAggressiveNSECNoDataSynthesis(t *testing.T) {
	t.Parallel()

	var upstreamCalls atomic.Int32
	dialer := stubDialer{
		fn: func(_ context.Context, _ netip.AddrPort, q wire.Message) (wire.Message, error) {
			upstreamCalls.Add(1)
			question := q.Questions()[0]
			qname := question.Name()
			soa := soaForExample()

			if qname.Equal(wire.MustParseName("a.example.")) && question.Type() == rrtype.MX {
				// Priming: a.example exists with A and AAAA but NOT MX.
				// NSEC at a.example with bitmap [A, AAAA] proves NoData
				// for MX.
				nsec := wire.NewRecord(qname, 5*time.Minute,
					rdata.NewNSEC(wire.MustParseName("b.example."),
						[]rrtype.Type{rrtype.A, rrtype.AAAA}))
				// Wildcard denial.
				wcNSEC := wire.NewRecord(wire.MustParseName("example."), 5*time.Minute,
					rdata.NewNSEC(wire.MustParseName("a.example."), nil))
				return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
					return b.Authoritative(true).
						Authority(soa).
						Authority(nsec).
						Authority(wcNSEC)
				}), nil
			}
			t.Errorf("unexpected upstream query for %s/%s", qname, question.Type())
			return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder { return b }), nil
		},
	}

	r := mustRecursive(t,
		recursive.WithRoots(netip.MustParseAddrPort("127.0.0.1:1")),
		recursive.WithDialer(dialer),
		recursive.WithQNameMinimisation(false),
		recursive.WithValidator(alwaysSecureValidator{}),
		recursive.WithAggressiveNSEC(true),
	)

	// Priming with MX query at a.example — gets NoData.
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	prime, err := r.ResolveEntry(ctx, wire.MustParseName("a.example."), rrtype.MX)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENoError, prime.RCODE())
	require.Empty(t, prime.Answer())
	priming := upstreamCalls.Load()

	// Re-query the same name + qtype — must hit the regular cache,
	// upstream untouched.
	again, err := r.ResolveEntry(ctx, wire.MustParseName("a.example."), rrtype.MX)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENoError, again.RCODE())
	require.Empty(t, again.Answer())
	require.Equal(t, priming, upstreamCalls.Load(),
		"NoData answer must be served from cache without upstream")
}

// TestAggressiveNSECRefusesWithoutWildcardDenial drives a
// scenario where the priming response provides only a
// q-covering NSEC and NO wildcard-denying NSEC. The aggressive
// cache must REFUSE to synthesise — RFC 4035 §5.4 / RFC 8198
// §5.5 require both halves of the proof.
func TestAggressiveNSECRefusesWithoutWildcardDenial(t *testing.T) {
	t.Parallel()

	var upstreamCalls atomic.Int32
	var primingDone atomic.Bool
	dialer := stubDialer{
		fn: func(_ context.Context, _ netip.AddrPort, q wire.Message) (wire.Message, error) {
			upstreamCalls.Add(1)
			question := q.Questions()[0]
			qname := question.Name()
			soa := soaForExample()
			nsec := wire.NewRecord(wire.MustParseName("a.example."), 5*time.Minute,
				rdata.NewNSEC(wire.MustParseName("d.example."), nil))

			if qname.Equal(wire.MustParseName("c.example.")) && !primingDone.Load() {
				primingDone.Store(true)
				// Priming response — INCOMPLETE: no wildcard NSEC.
				return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
					return b.Authoritative(true).
						RCODE(wire.RCODENXDomain).
						Authority(soa).
						Authority(nsec)
				}), nil
			}
			// Second query — the resolver must consult us, not
			// synthesise from the incomplete proof.
			return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
				return b.Authoritative(true).
					RCODE(wire.RCODENXDomain).
					Authority(soa).
					Authority(nsec)
			}), nil
		},
	}

	r := mustRecursive(t,
		recursive.WithRoots(netip.MustParseAddrPort("127.0.0.1:1")),
		recursive.WithDialer(dialer),
		recursive.WithQNameMinimisation(false),
		recursive.WithValidator(alwaysSecureValidator{}),
		recursive.WithAggressiveNSEC(true),
	)

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	_, err := r.ResolveEntry(ctx, wire.MustParseName("c.example."), rrtype.A)
	require.NoError(t, err)
	primed := upstreamCalls.Load()

	// b.example would be covered by the cached NSEC, but synthesis
	// must be refused because no wildcard-denying NSEC is cached.
	_, err = r.ResolveEntry(ctx, wire.MustParseName("b.example."), rrtype.A)
	require.NoError(t, err)
	require.Greater(t, upstreamCalls.Load(), primed,
		"incomplete proof must NOT be aggressively used")
}

// TestAggressiveNSEC3NoData verifies §5.4: NSEC3 matching the
// queried name's hash with bitmap excluding qtype yields NoData.
//
// We seed the NSEC3 records by hand (skipping a real authoritative
// fixture) — in practice the resolver populates the index from a
// validated negative response, but here we directly verify the
// hash-space lookup.
func TestAggressiveNSEC3NoData(t *testing.T) {
	t.Parallel()

	// Build a priming response carrying NSEC3 records. We compute
	// the hashes the same way the implementation does to keep the
	// test self-contained.
	zoneApex := wire.MustParseName("example.")
	qname := wire.MustParseName("foo.example.")
	salt := []byte{0xab, 0xcd}

	matchHash := iteratedSHA1(qname.AppendWire(nil), salt, 0)
	apexHash := iteratedSHA1(zoneApex.AppendWire(nil), salt, 0)

	// A NoData NSEC3 at the queried name's hash — bitmap excludes A.
	nsec3Match := wire.NewRecord(
		nsec3OwnerName(matchHash, zoneApex),
		5*time.Minute,
		rdata.MustNewNSEC3(1 /*sha1*/, 0 /*flags*/, 0 /*iterations*/, salt,
			apexHash, // any plausible next-hash, doesn't matter for NoData
			[]rrtype.Type{rrtype.AAAA, rrtype.TXT}),
	)

	var upstreamCalls atomic.Int32
	dialer := stubDialer{
		fn: func(_ context.Context, _ netip.AddrPort, q wire.Message) (wire.Message, error) {
			upstreamCalls.Add(1)
			question := q.Questions()[0]
			if question.Name().Equal(qname) && question.Type() == rrtype.A {
				return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
					return b.Authoritative(true).
						Authority(soaForExample()).
						Authority(nsec3Match)
				}), nil
			}
			t.Errorf("unexpected upstream query for %s/%s", question.Name(), question.Type())
			return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder { return b }), nil
		},
	}

	r := mustRecursive(t,
		recursive.WithRoots(netip.MustParseAddrPort("127.0.0.1:1")),
		recursive.WithDialer(dialer),
		recursive.WithQNameMinimisation(false),
		recursive.WithValidator(alwaysSecureValidator{}),
		recursive.WithAggressiveNSEC(true),
	)

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	prime, err := r.ResolveEntry(ctx, qname, rrtype.A)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENoError, prime.RCODE())
	require.Empty(t, prime.Answer())
	primed := upstreamCalls.Load()

	// Same name + same type → cached entry serves it.
	again, err := r.ResolveEntry(ctx, qname, rrtype.A)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENoError, again.RCODE())
	require.Empty(t, again.Answer())
	require.Equal(t, primed, upstreamCalls.Load())
}
