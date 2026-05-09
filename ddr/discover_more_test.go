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

// fakeRecord is a wire.Record implementation that lets tests force a
// mismatch between the reported Type() and the dynamic type of RData().
type fakeRecord struct {
	name  wire.Name
	typ   rrtype.Type
	class rrtype.Class
	ttl   time.Duration
	rd    rdata.RData
}

func (r fakeRecord) Name() wire.Name     { return r.name }
func (r fakeRecord) Type() rrtype.Type   { return r.typ }
func (r fakeRecord) Class() rrtype.Class { return r.class }
func (r fakeRecord) TTL() time.Duration  { return r.ttl }
func (r fakeRecord) RData() rdata.RData  { return r.rd }

func TestDiscover_ResolverError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("upstream boom")
	endpoints, err := ddr.Discover(t.Context(), &errResolver{err: sentinel})
	require.ErrorIs(t, err, sentinel)
	require.Nil(t, endpoints)
}

func TestDiscover_SkipsNonSVCB(t *testing.T) {
	t.Parallel()

	// Non-SVCB record: an A record snuck into the answer section.
	aRec := wire.NewRecord(ddr.ResolverDomain(), 60*time.Second,
		rdata.MustNewA(netip.MustParseAddr("192.0.2.42")))

	// A SVCB rrtype slot whose RData is NOT an rdata.SVCB — exercise the
	// "type assertion failed" guard inside Discover.
	mismatched := fakeRecord{
		name:  ddr.ResolverDomain(),
		typ:   rrtype.SVCB,
		class: rrtype.ClassIN,
		ttl:   60 * time.Second,
		rd:    rdata.NewUnknown(rrtype.SVCB, []byte{0x00}),
	}

	// AliasMode SVCB (priority 0) — must be filtered.
	alias := rdata.MustNewSVCB(0, wire.MustParseName("alias.example.net"))
	aliasRec := wire.NewRecord(ddr.ResolverDomain(), 60*time.Second, alias)

	// One legitimate ServiceMode SVCB so the result list is non-empty.
	alpnDoT, err := rdata.NewSvcParamALPN("dot")
	require.NoError(t, err)
	good := rdata.MustNewSVCB(5, wire.MustParseName("dot.example.net"), alpnDoT,
		rdata.NewSvcParamPort(853))
	goodRec := wire.NewRecord(ddr.ResolverDomain(), 60*time.Second, good)

	r := &fakeResolver{answer: newFakeAnswer(nil, []wire.Record{
		aRec, mismatched, aliasRec, goodRec,
	})}
	endpoints, err := ddr.Discover(t.Context(), r)
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
	hi := rdata.MustNewSVCB(10, wire.MustParseName("hi.example.net"), alpnDoT)
	lo := rdata.MustNewSVCB(1, wire.MustParseName("lo.example.net"), alpnDoT)
	mid := rdata.MustNewSVCB(5, wire.MustParseName("mid.example.net"), alpnDoT)

	records := []wire.Record{
		wire.NewRecord(ddr.ResolverDomain(), 60*time.Second, hi),
		wire.NewRecord(ddr.ResolverDomain(), 60*time.Second, lo),
		wire.NewRecord(ddr.ResolverDomain(), 60*time.Second, mid),
	}
	r := &fakeResolver{answer: newFakeAnswer(nil, records)}
	endpoints, err := ddr.Discover(t.Context(), r)
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
	h3SVCB := rdata.MustNewSVCB(1, wire.MustParseName("h3.example.net"), alpnH3)

	alpnH1, err := rdata.NewSvcParamALPN("http/1.1")
	require.NoError(t, err)
	h1SVCB := rdata.MustNewSVCB(2, wire.MustParseName("h1.example.net"), alpnH1)

	alpnDoQ, err := rdata.NewSvcParamALPN("doq")
	require.NoError(t, err)
	doqSVCB := rdata.MustNewSVCB(3, wire.MustParseName("doq.example.net"), alpnDoQ,
		rdata.NewSvcParamPort(853))

	// No ALPN, no DOHPath → ProtoUnknown.
	bareSVCB := rdata.MustNewSVCB(4, wire.MustParseName("bare.example.net"))

	// Mixed case ALPN — exercise the strings.ToLower normalization.
	alpnMixed, err := rdata.NewSvcParamALPN("DoT")
	require.NoError(t, err)
	mixedSVCB := rdata.MustNewSVCB(5, wire.MustParseName("mixed.example.net"), alpnMixed)

	records := []wire.Record{
		wire.NewRecord(ddr.ResolverDomain(), 60*time.Second, h3SVCB),
		wire.NewRecord(ddr.ResolverDomain(), 60*time.Second, h1SVCB),
		wire.NewRecord(ddr.ResolverDomain(), 60*time.Second, doqSVCB),
		wire.NewRecord(ddr.ResolverDomain(), 60*time.Second, bareSVCB),
		wire.NewRecord(ddr.ResolverDomain(), 60*time.Second, mixedSVCB),
	}
	r := &fakeResolver{answer: newFakeAnswer(nil, records)}
	endpoints, err := ddr.Discover(t.Context(), r)
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
	s := rdata.MustNewSVCB(1, wire.MustParseName("dot.example.net"),
		alpnDoT,
		rdata.NewSvcParamPort(853),
		v6hint,
	)
	rec := wire.NewRecord(ddr.ResolverDomain(), 60*time.Second, s)
	r := &fakeResolver{answer: newFakeAnswer(nil, []wire.Record{rec})}
	endpoints, err := ddr.Discover(t.Context(), r)
	require.NoError(t, err)
	require.Len(t, endpoints, 1)
	require.Equal(t, ddr.ProtoDoT, endpoints[0].Protocol())
	require.Len(t, endpoints[0].IPv6Hints(), 1)
	require.Equal(t, netip.MustParseAddr("2001:db8::1"), endpoints[0].IPv6Hints()[0])
}
