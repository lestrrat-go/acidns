package dnsclient_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient"
	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/stretchr/testify/require"
)

type fakeExchanger func(context.Context, dnsmsg.Message) (dnsmsg.Message, error)

func (f fakeExchanger) Exchange(ctx context.Context, q dnsmsg.Message) (dnsmsg.Message, error) {
	return f(ctx, q)
}

func TestTCFallbackUsesPrimaryWhenNotTruncated(t *testing.T) {
	t.Parallel()

	primary := fakeExchanger(func(_ context.Context, q dnsmsg.Message) (dnsmsg.Message, error) {
		return dnsmsg.NewBuilder().
			ID(q.ID()).
			Response(true).
			RecursionAvailable(true).
			Question(q.Questions()[0]).
			Answer(dnsmsg.NewRecord(q.Questions()[0].Name(), time.Minute,
				rdata.NewA(netip.MustParseAddr("203.0.113.10")))).
			Build()
	})
	fallback := fakeExchanger(func(_ context.Context, q dnsmsg.Message) (dnsmsg.Message, error) {
		t.Fatalf("fallback should not be invoked")
		return nil, nil
	})

	r, err := dnsclient.New(dnsclient.WithExchanger(dnsclient.WrapWithTCFallback(primary, fallback)))
	require.NoError(t, err)
	ans, err := r.Resolve(t.Context(), dnsname.MustParse("example.com"), rrtype.A)
	require.NoError(t, err)
	require.Equal(t, "203.0.113.10", ans.Records()[0].RData().(rdata.A).Addr().String())
}

func TestTCFallbackRetriesTruncated(t *testing.T) {
	t.Parallel()

	primary := fakeExchanger(func(_ context.Context, q dnsmsg.Message) (dnsmsg.Message, error) {
		return dnsmsg.NewBuilder().
			ID(q.ID()).
			Response(true).
			Truncated(true).
			Question(q.Questions()[0]).
			Build()
	})
	fallback := fakeExchanger(func(_ context.Context, q dnsmsg.Message) (dnsmsg.Message, error) {
		return dnsmsg.NewBuilder().
			ID(q.ID()).
			Response(true).
			Question(q.Questions()[0]).
			Answer(dnsmsg.NewRecord(q.Questions()[0].Name(), time.Minute,
				rdata.NewA(netip.MustParseAddr("203.0.113.20")))).
			Build()
	})

	r, err := dnsclient.New(dnsclient.WithExchanger(dnsclient.WrapWithTCFallback(primary, fallback)))
	require.NoError(t, err)
	ans, err := r.Resolve(t.Context(), dnsname.MustParse("example.com"), rrtype.A)
	require.NoError(t, err)
	require.Equal(t, "203.0.113.20", ans.Records()[0].RData().(rdata.A).Addr().String())
}
