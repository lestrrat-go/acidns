package acidns_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// failExchanger panics if invoked — used to prove the resolver
// short-circuits before issuing a network query.
type failExchanger struct{ t *testing.T }

func (f failExchanger) Exchange(_ context.Context, _ wire.Message) (wire.Message, error) {
	f.t.Fatal("network exchange must not be invoked for special-use names")
	return nil, nil //nolint:nilnil // unreachable after t.Fatal
}

func TestSpecialUseLocalhostA(t *testing.T) {
	t.Parallel()
	r, err := acidns.NewResolver(acidns.WithExchanger(failExchanger{t}))
	require.NoError(t, err)

	ans, err := r.Resolve(t.Context(), wire.MustParseName("localhost"), rrtype.A)
	require.NoError(t, err)
	require.Equal(t, 1, len(ans.Records()))
	require.Equal(t, "127.0.0.1", ans.Records()[0].RData().(rdata.A).Addr().String())
}

func TestSpecialUseLocalhostAAAA(t *testing.T) {
	t.Parallel()
	r, err := acidns.NewResolver(acidns.WithExchanger(failExchanger{t}))
	require.NoError(t, err)
	ans, err := r.Resolve(t.Context(), wire.MustParseName("foo.localhost"), rrtype.AAAA)
	require.NoError(t, err)
	require.Equal(t, 1, len(ans.Records()))
	require.Equal(t, "::1", ans.Records()[0].RData().(rdata.AAAA).Addr().String())
}

func TestSpecialUseInvalid(t *testing.T) {
	t.Parallel()
	r, err := acidns.NewResolver(acidns.WithExchanger(failExchanger{t}))
	require.NoError(t, err)
	_, err = r.Resolve(t.Context(), wire.MustParseName("nope.invalid"), rrtype.A)
	require.ErrorIs(t, err, acidns.ErrNXDOMAIN)
	var rerr *acidns.RCodeError
	require.ErrorAs(t, err, &rerr)
	require.Equal(t, wire.RCODENXDomain, rerr.Answer.RCODE())
}

// recordingExchanger captures the most recent question so tests can assert
// the resolver did or did not reach the network for a given query.
type recordingExchanger struct{ called bool }

func (r *recordingExchanger) Exchange(_ context.Context, q wire.Message) (wire.Message, error) {
	r.called = true
	resp, _ := wire.NewBuilder().
		ID(q.ID()).
		Response(true).
		Question(q.Questions()[0]).
		Answer(wire.NewRecord(q.Questions()[0].Name(), 0,
			rdata.NewA(netip.MustParseAddr("192.0.2.1")))).
		Build()
	return resp, nil
}

func TestSpecialUseDisabled(t *testing.T) {
	t.Parallel()
	rec := &recordingExchanger{}
	r, err := acidns.NewResolver(
		acidns.WithExchanger(rec),
		acidns.WithSpecialUse(false),
	)
	require.NoError(t, err)
	ans, err := r.Resolve(t.Context(), wire.MustParseName("anything.localhost"), rrtype.A)
	require.NoError(t, err)
	require.True(t, rec.called, "with WithSpecialUse(false) the network must be used")
	require.Equal(t, 1, len(ans.Records()))
	require.Equal(t, "192.0.2.1", ans.Records()[0].RData().(rdata.A).Addr().String())
}
