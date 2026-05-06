package dnsclient_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/lestrrat-go/acidns/dnsclient"
	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/stretchr/testify/require"
)

// failExchanger panics if invoked — used to prove the resolver
// short-circuits before issuing a network query.
type failExchanger struct{ t *testing.T }

func (f failExchanger) Exchange(_ context.Context, _ dnsmsg.Message) (dnsmsg.Message, error) {
	f.t.Fatal("network exchange must not be invoked for special-use names")
	return nil, nil
}

func TestSpecialUseLocalhostA(t *testing.T) {
	t.Parallel()
	r, err := dnsclient.New(dnsclient.WithExchanger(failExchanger{t}))
	require.NoError(t, err)

	ans, err := r.Resolve(t.Context(), dnsname.MustParse("localhost"), rrtype.A)
	require.NoError(t, err)
	require.Equal(t, 1, len(ans.Records()))
	require.Equal(t, "127.0.0.1", ans.Records()[0].RData().(rdata.A).Addr().String())
}

func TestSpecialUseLocalhostAAAA(t *testing.T) {
	t.Parallel()
	r, err := dnsclient.New(dnsclient.WithExchanger(failExchanger{t}))
	require.NoError(t, err)
	ans, err := r.Resolve(t.Context(), dnsname.MustParse("foo.localhost"), rrtype.AAAA)
	require.NoError(t, err)
	require.Equal(t, 1, len(ans.Records()))
	require.Equal(t, "::1", ans.Records()[0].RData().(rdata.AAAA).Addr().String())
}

func TestSpecialUseInvalid(t *testing.T) {
	t.Parallel()
	r, err := dnsclient.New(dnsclient.WithExchanger(failExchanger{t}))
	require.NoError(t, err)
	ans, err := r.Resolve(t.Context(), dnsname.MustParse("nope.invalid"), rrtype.A)
	require.NoError(t, err)
	require.Equal(t, dnsmsg.RCODENXDomain, ans.RCODE())
}

// recordingExchanger captures the most recent question so tests can assert
// the resolver did or did not reach the network for a given query.
type recordingExchanger struct{ called bool }

func (r *recordingExchanger) Exchange(_ context.Context, q dnsmsg.Message) (dnsmsg.Message, error) {
	r.called = true
	resp, _ := dnsmsg.NewBuilder().
		ID(q.ID()).
		Response(true).
		Question(q.Questions()[0]).
		Answer(dnsmsg.NewRecord(q.Questions()[0].Name(), 0,
			rdata.NewA(netip.MustParseAddr("192.0.2.1")))).
		Build()
	return resp, nil
}

func TestSpecialUseDisabled(t *testing.T) {
	t.Parallel()
	rec := &recordingExchanger{}
	r, err := dnsclient.New(
		dnsclient.WithExchanger(rec),
		dnsclient.WithoutSpecialUse(),
	)
	require.NoError(t, err)
	ans, err := r.Resolve(t.Context(), dnsname.MustParse("anything.localhost"), rrtype.A)
	require.NoError(t, err)
	require.True(t, rec.called, "with WithoutSpecialUse the network must be used")
	require.Equal(t, 1, len(ans.Records()))
	require.Equal(t, "192.0.2.1", ans.Records()[0].RData().(rdata.A).Addr().String())
}
