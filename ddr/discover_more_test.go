package ddr_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/ddr"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// errResolver always returns an error from Resolve.
type errResolver struct {
	err error
}

func (e *errResolver) Resolve(_ context.Context, _ wire.Name, _ rrtype.Type) (*acidns.Answer, error) {
	return nil, e.err
}

func TestDiscover_ResolverError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("upstream boom")
	endpoints, err := ddr.DiscoverUnverified(t.Context(), &errResolver{err: sentinel})
	require.ErrorIs(t, err, sentinel)
	require.Nil(t, endpoints)
}

func TestDiscover_SkipsNonSVCB(t *testing.T) {
	t.Parallel()

	// Non-SVCB record: an A record snuck into the answer section.
	ar, err := rdata.NewA(netip.MustParseAddr("192.0.2.42"))
	require.NoError(t, err)
	aRec := wire.NewRecord(ddr.ResolverDomain(), 60*time.Second,
		ar)

	// AliasMode SVCB (priority 0) — must be filtered.
	alias, err := rdata.NewSVCB(0, wire.MustParseName("alias.example.net"))
	require.NoError(t, err)
	aliasRec := wire.NewRecord(ddr.ResolverDomain(), 60*time.Second, alias)

	// One legitimate ServiceMode SVCB so the result list is non-empty.
	alpnDoT, err := rdata.NewSvcParamALPN("dot")
	require.NoError(t, err)
	good, err := rdata.NewSVCB(5, wire.MustParseName("dot.example.net"), alpnDoT,
		rdata.NewSvcParamPort(853))
	require.NoError(t, err)
	goodRec := wire.NewRecord(ddr.ResolverDomain(), 60*time.Second, good)

	r := &fakeResolver{answer: newFakeAnswer(wire.Question{}, []wire.Record{
		aRec, aliasRec, goodRec,
	})}
	endpoints, err := ddr.DiscoverUnverified(t.Context(), r)
	require.NoError(t, err)
	require.Len(t, endpoints, 1)
	require.Equal(t, ddr.ProtoDoT, endpoints[0].Protocol())
	require.Equal(t, uint16(853), endpoints[0].Port())
	require.Equal(t, uint16(5), endpoints[0].Priority())
}

func TestDiscover_SortsByPriority(t *testing.T) {
	t.Parallel()

	alpnDoT, err := rdata.NewSvcParamALPN("dot")
	require.NoError(t, err)
	hi, err := rdata.NewSVCB(10, wire.MustParseName("hi.example.net"), alpnDoT)
	require.NoError(t, err)
	lo, err := rdata.NewSVCB(1, wire.MustParseName("lo.example.net"), alpnDoT)
	require.NoError(t, err)
	mid, err := rdata.NewSVCB(5, wire.MustParseName("mid.example.net"), alpnDoT)
	require.NoError(t, err)

	records := []wire.Record{
		wire.NewRecord(ddr.ResolverDomain(), 60*time.Second, hi),
		wire.NewRecord(ddr.ResolverDomain(), 60*time.Second, lo),
		wire.NewRecord(ddr.ResolverDomain(), 60*time.Second, mid),
	}
	r := &fakeResolver{answer: newFakeAnswer(wire.Question{}, records)}
	endpoints, err := ddr.DiscoverUnverified(t.Context(), r)
	require.NoError(t, err)
	require.Len(t, endpoints, 3)
	require.Equal(t, uint16(1), endpoints[0].Priority())
	require.Equal(t, uint16(5), endpoints[1].Priority())
	require.Equal(t, uint16(10), endpoints[2].Priority())
}

// TestDiscover_InferProtocolVariants exercises every branch of
// inferProtocol via Discover end-to-end: h3, http/1.1, doq, and an
// empty-ALPN entry that falls through to ProtoUnknown.
func TestDiscover_InferProtocolVariants(t *testing.T) {
	t.Parallel()

	alpnH3, err := rdata.NewSvcParamALPN("h3")
	require.NoError(t, err)
	h3SVCB, err := rdata.NewSVCB(1, wire.MustParseName("h3.example.net"), alpnH3)
	require.NoError(t, err)

	alpnH1, err := rdata.NewSvcParamALPN("http/1.1")
	require.NoError(t, err)
	h1SVCB, err := rdata.NewSVCB(2, wire.MustParseName("h1.example.net"), alpnH1)
	require.NoError(t, err)

	alpnDoQ, err := rdata.NewSvcParamALPN("doq")
	require.NoError(t, err)
	doqSVCB, err := rdata.NewSVCB(3, wire.MustParseName("doq.example.net"), alpnDoQ,
		rdata.NewSvcParamPort(853))
	require.NoError(t, err)

	// No ALPN, no DOHPath → ProtoUnknown.
	bareSVCB, err := rdata.NewSVCB(4, wire.MustParseName("bare.example.net"))
	require.NoError(t, err)

	// Mixed case ALPN — exercise the strings.ToLower normalization.
	alpnMixed, err := rdata.NewSvcParamALPN("DoT")
	require.NoError(t, err)
	mixedSVCB, err := rdata.NewSVCB(5, wire.MustParseName("mixed.example.net"), alpnMixed)
	require.NoError(t, err)

	records := []wire.Record{
		wire.NewRecord(ddr.ResolverDomain(), 60*time.Second, h3SVCB),
		wire.NewRecord(ddr.ResolverDomain(), 60*time.Second, h1SVCB),
		wire.NewRecord(ddr.ResolverDomain(), 60*time.Second, doqSVCB),
		wire.NewRecord(ddr.ResolverDomain(), 60*time.Second, bareSVCB),
		wire.NewRecord(ddr.ResolverDomain(), 60*time.Second, mixedSVCB),
	}
	r := &fakeResolver{answer: newFakeAnswer(wire.Question{}, records)}
	endpoints, err := ddr.DiscoverUnverified(t.Context(), r)
	require.NoError(t, err)
	require.Len(t, endpoints, 5)

	byPriority := map[uint16]ddr.Endpoint{}
	for _, ep := range endpoints {
		byPriority[ep.Priority()] = ep
	}
	require.Equal(t, ddr.ProtoDoH, byPriority[1].Protocol(), "h3 → DoH")
	require.Equal(t, ddr.ProtoDoH, byPriority[2].Protocol(), "http/1.1 → DoH")
	require.Equal(t, ddr.ProtoDoQ, byPriority[3].Protocol(), "doq → DoQ")
	require.Equal(t, ddr.ProtoUnknown, byPriority[4].Protocol(), "no hints → unknown")
	require.Equal(t, ddr.ProtoDoT, byPriority[5].Protocol(), "DoT (mixed-case) → DoT")
}

func TestDiscover_IPv6Hints(t *testing.T) {
	t.Parallel()

	alpnDoT, err := rdata.NewSvcParamALPN("dot")
	require.NoError(t, err)
	v6hint, err := rdata.NewSvcParamIPv6Hint(netip.MustParseAddr("2001:db8::1"))
	require.NoError(t, err)
	s, err := rdata.NewSVCB(1, wire.MustParseName("dot.example.net"),
		alpnDoT,
		rdata.NewSvcParamPort(853),
		v6hint,
	)
	require.NoError(t, err)
	rec := wire.NewRecord(ddr.ResolverDomain(), 60*time.Second, s)
	r := &fakeResolver{answer: newFakeAnswer(wire.Question{}, []wire.Record{rec})}
	endpoints, err := ddr.DiscoverUnverified(t.Context(), r)
	require.NoError(t, err)
	require.Len(t, endpoints, 1)
	require.Equal(t, ddr.ProtoDoT, endpoints[0].Protocol())
	require.Len(t, endpoints[0].IPv6Hints(), 1)
	require.Equal(t, netip.MustParseAddr("2001:db8::1"), endpoints[0].IPv6Hints()[0])
}
