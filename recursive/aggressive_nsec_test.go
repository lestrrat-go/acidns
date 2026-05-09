package recursive_test

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/recursive"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// alwaysSecureValidator marks every Resolve as Secure so the
// resolver's AD-tagging path runs and the aggressive NSEC index
// gets populated. Tests that need Bogus or Insecure use a
// different validator stub.
type alwaysSecureValidator struct{}

func (alwaysSecureValidator) Resolve(_ context.Context, _ wire.Name, _ rrtype.Type) (recursive.ValidationResult, error) {
	return secureResult{}, nil
}

type secureResult struct{}

func (secureResult) Result() recursive.ValidationStatus { return recursive.StatusSecure }
func (secureResult) Records() []wire.Record             { return nil }
func (secureResult) RCODE() wire.RCODE                  { return wire.RCODENoError }
func (secureResult) Reason() error                      { return nil }

// TestAggressiveNSECSynthesisesNXDOMAIN drives a resolver that has
// previously cached a validated NSEC interval [a.example, d.example).
// A new query for b.example — which the resolver has never asked
// for — must be answered NXDOMAIN locally without contacting the
// upstream.
func TestAggressiveNSECSynthesisesNXDOMAIN(t *testing.T) {
	t.Parallel()

	var upstreamCalls atomic.Int32
	dialer := stubDialer{
		fn: func(_ context.Context, _ netip.AddrPort, q wire.Message) (wire.Message, error) {
			upstreamCalls.Add(1)
			question := q.Questions()[0]
			qname := question.Name()

			// First query (priming): respond NXDOMAIN with a covering
			// NSEC + an SOA. The resolver caches the NSEC.
			soa := wire.NewRecord(wire.MustParseName("example."), 5*time.Minute,
				rdata.NewSOA(
					wire.MustParseName("ns.example."),
					wire.MustParseName("hm.example."),
					1, 7200, 3600, 1209600, 60,
				))
			nsec := wire.NewRecord(wire.MustParseName("a.example."), 5*time.Minute,
				rdata.NewNSEC(wire.MustParseName("d.example."), nil))

			if qname.Equal(wire.MustParseName("c.example.")) {
				// Priming query: the response proves c.example doesn't
				// exist via the NSEC interval [a, d).
				return mkResp(t, q, func(b *wire.Builder) *wire.Builder {
					return b.Authoritative(true).
						RCODE(wire.RCODENXDomain).
						Authority(soa).
						Authority(nsec)
				}), nil
			}
			// Any other query: this should never run for b.example
			// because the aggressive cache must intercept it.
			t.Errorf("unexpected upstream query for %s", qname)
			return mkResp(t, q, func(b *wire.Builder) *wire.Builder {
				return b.Authoritative(true).RCODE(wire.RCODENXDomain).Authority(soa)
			}), nil
		},
	}

	r := recursive.New(
		recursive.WithRoots(netip.MustParseAddrPort("127.0.0.1:1")),
		recursive.WithDialer(dialer),
		recursive.WithoutQNameMinimisation(),
		recursive.WithValidator(alwaysSecureValidator{}),
		recursive.WithAggressiveNSEC(),
	)

	// Priming: c.example. → NXDOMAIN, validated, cached + indexed.
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	prime, err := r.Resolve(ctx, wire.MustParseName("c.example."), rrtype.A)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENXDomain, prime.RCODE)
	require.True(t, prime.AD)
	priming := upstreamCalls.Load()

	// Aggressive use: b.example. — never queried — must synthesise.
	syn, err := r.Resolve(ctx, wire.MustParseName("b.example."), rrtype.A)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENXDomain, syn.RCODE)
	require.True(t, syn.AD, "synthesised entry must carry AD")
	require.Equal(t, priming, upstreamCalls.Load(),
		"aggressive NSEC must NOT consult the upstream for a covered name")
}

// TestAggressiveNSECDisabledByDefault verifies the option is opt-in:
// an otherwise identically configured resolver without
// WithAggressiveNSEC consults the upstream for the second query.
func TestAggressiveNSECDisabledByDefault(t *testing.T) {
	t.Parallel()

	var upstreamCalls atomic.Int32
	dialer := stubDialer{
		fn: func(_ context.Context, _ netip.AddrPort, q wire.Message) (wire.Message, error) {
			upstreamCalls.Add(1)
			soa := wire.NewRecord(wire.MustParseName("example."), 5*time.Minute,
				rdata.NewSOA(
					wire.MustParseName("ns.example."),
					wire.MustParseName("hm.example."),
					1, 7200, 3600, 1209600, 60,
				))
			nsec := wire.NewRecord(wire.MustParseName("a.example."), 5*time.Minute,
				rdata.NewNSEC(wire.MustParseName("d.example."), nil))
			return mkResp(t, q, func(b *wire.Builder) *wire.Builder {
				return b.Authoritative(true).
					RCODE(wire.RCODENXDomain).
					Authority(soa).
					Authority(nsec)
			}), nil
		},
	}

	r := recursive.New(
		recursive.WithRoots(netip.MustParseAddrPort("127.0.0.1:1")),
		recursive.WithDialer(dialer),
		recursive.WithoutQNameMinimisation(),
		recursive.WithValidator(alwaysSecureValidator{}),
		// NO WithAggressiveNSEC
	)

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	_, err := r.Resolve(ctx, wire.MustParseName("c.example."), rrtype.A)
	require.NoError(t, err)
	primed := upstreamCalls.Load()

	_, err = r.Resolve(ctx, wire.MustParseName("b.example."), rrtype.A)
	require.NoError(t, err)
	require.Greater(t, upstreamCalls.Load(), primed,
		"without WithAggressiveNSEC the second name must consult upstream")
}

// TestAggressiveNSECNoValidatorIsNoop verifies WithAggressiveNSEC
// without WithValidator does nothing — index stays empty so no
// synthesis can occur (every query goes upstream).
func TestAggressiveNSECNoValidatorIsNoop(t *testing.T) {
	t.Parallel()

	var upstreamCalls atomic.Int32
	dialer := stubDialer{
		fn: func(_ context.Context, _ netip.AddrPort, q wire.Message) (wire.Message, error) {
			upstreamCalls.Add(1)
			soa := wire.NewRecord(wire.MustParseName("example."), 5*time.Minute,
				rdata.NewSOA(
					wire.MustParseName("ns.example."),
					wire.MustParseName("hm.example."),
					1, 7200, 3600, 1209600, 60,
				))
			nsec := wire.NewRecord(wire.MustParseName("a.example."), 5*time.Minute,
				rdata.NewNSEC(wire.MustParseName("d.example."), nil))
			return mkResp(t, q, func(b *wire.Builder) *wire.Builder {
				return b.Authoritative(true).
					RCODE(wire.RCODENXDomain).
					Authority(soa).
					Authority(nsec)
			}), nil
		},
	}

	r := recursive.New(
		recursive.WithRoots(netip.MustParseAddrPort("127.0.0.1:1")),
		recursive.WithDialer(dialer),
		recursive.WithoutQNameMinimisation(),
		// AggressiveNSEC without Validator — the resolver internally
		// disables it because the safety property requires
		// validation.
		recursive.WithAggressiveNSEC(),
	)

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	_, err := r.Resolve(ctx, wire.MustParseName("c.example."), rrtype.A)
	require.NoError(t, err)
	primed := upstreamCalls.Load()

	_, err = r.Resolve(ctx, wire.MustParseName("b.example."), rrtype.A)
	require.NoError(t, err)
	require.Greater(t, upstreamCalls.Load(), primed,
		"without a validator the aggressive cache stays empty")
}
