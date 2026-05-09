package ddr_test

import (
	"context"
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

type fakeResolver struct {
	answer *acidns.Answer
}

func (f *fakeResolver) Resolve(_ context.Context, _ wire.Name, _ rrtype.Type) (*acidns.Answer, error) {
	return f.answer, nil
}

func newFakeAnswer(q wire.Question, records []wire.Record) *acidns.Answer {
	raw, _ := wire.NewBuilder().Response(true).Build()
	return acidns.NewAnswer(q, records, raw)
}

func TestDiscover(t *testing.T) {
	t.Parallel()

	alpnH2, err := rdata.NewSvcParamALPN("h2")
	require.NoError(t, err)
	v4hint, err := rdata.NewSvcParamIPv4Hint(netip.MustParseAddr("192.0.2.1"))
	require.NoError(t, err)
	dohSVCB := rdata.MustNewSVCB(1, wire.MustParseName("doh.example.net"),
		alpnH2,
		rdata.NewSvcParamPort(443),
		rdata.NewSvcParamDOHPath("/dns-query{?dns}"),
		v4hint,
	)

	alpnDoT, err := rdata.NewSvcParamALPN("dot")
	require.NoError(t, err)
	dotSVCB := rdata.MustNewSVCB(2, wire.MustParseName("dot.example.net"),
		alpnDoT,
		rdata.NewSvcParamPort(853),
	)

	rec1 := wire.NewRecord(ddr.ResolverDomain, 60*time.Second, dohSVCB)
	rec2 := wire.NewRecord(ddr.ResolverDomain, 60*time.Second, dotSVCB)

	r := &fakeResolver{answer: newFakeAnswer(nil, []wire.Record{rec1, rec2})}
	endpoints, err := ddr.Discover(context.Background(), r)
	require.NoError(t, err)
	require.Len(t, endpoints, 2)

	require.Equal(t, ddr.ProtoDoH, endpoints[0].Protocol)
	require.Equal(t, "/dns-query{?dns}", endpoints[0].DOHPath)
	require.Equal(t, uint16(443), endpoints[0].Port)
	require.Len(t, endpoints[0].IPv4Hints, 1)

	require.Equal(t, ddr.ProtoDoT, endpoints[1].Protocol)
	require.Equal(t, uint16(853), endpoints[1].Port)
}
