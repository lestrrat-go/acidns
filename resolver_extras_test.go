package acidns_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/specialuse"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

func TestRCodeErrorIs(t *testing.T) {
	t.Parallel()
	live := acidns.NewRCodeError(wire.RCODENXDomain, nil)
	require.True(t, errors.Is(live, acidns.ErrNXDOMAIN))
	require.False(t, errors.Is(live, acidns.ErrServFail))
	require.False(t, errors.Is(live, errors.New("other")))
	require.Equal(t, "acidns: NXDOMAIN", live.Error())
}

func TestSpecialUseLoopbackForType(t *testing.T) {
	t.Parallel()
	v4 := specialuse.LoopbackForType(rrtype.A)
	require.Len(t, v4, 1)
	require.Equal(t, "127.0.0.1", v4[0].String())

	v6 := specialuse.LoopbackForType(rrtype.AAAA)
	require.Len(t, v6, 1)
	require.Equal(t, "::1", v6[0].String())

	require.Empty(t, specialuse.LoopbackForType(rrtype.MX))
}

type stubExchanger struct {
	resp wire.Message
	err  error
}

func (s *stubExchanger) Exchange(_ context.Context, _ wire.Message) (wire.Message, error) {
	return s.resp, s.err
}

func TestNewWithExchanger(t *testing.T) {
	t.Parallel()
	r, err := acidns.NewResolver(acidns.WithExchanger(&stubExchanger{}))
	require.NoError(t, err)
	require.NotNil(t, r)
}

func TestNewRequiresSomething(t *testing.T) {
	t.Parallel()
	_, err := acidns.NewResolver()
	require.ErrorIs(t, err, acidns.ErrNoResolver)
}

func TestOptionAccessors(t *testing.T) {
	t.Parallel()
	// Just ensure each option compiles and applies without panic.
	_ = acidns.WithEDNSUDPSize(4096)
	_ = acidns.WithDNSSEC(true)
	_ = acidns.WithEDNS(false)
	_ = acidns.WithAttempts(3)
	_ = acidns.WithPerAttemptTimeout(time.Second)
	_ = acidns.WithSearchList(wire.MustParseName("example.com"))
	_ = acidns.WithNdots(2)
	_ = acidns.WithSpecialUse(false)
	_ = acidns.WithServers(netip.MustParseAddrPort("127.0.0.1:53"))
}

func TestAnswerMethods(t *testing.T) {
	t.Parallel()
	// Build a synthetic answer by exercising Resolve with a stub.
	q, err := wire.NewMessageBuilder().
		ID(1).
		Response(true).
		Authoritative(true).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	require.NoError(t, err)
	stub := &stubExchanger{resp: q}
	r, err := acidns.NewResolver(acidns.WithExchanger(stub), acidns.WithSpecialUse(false))
	require.NoError(t, err)
	ans, err := r.Resolve(context.Background(), wire.MustParseName("example.com"), rrtype.A)
	require.NoError(t, err)
	require.NotNil(t, ans.Question())
	require.NotNil(t, ans.Raw())
	require.True(t, ans.Authoritative())
	require.False(t, ans.Truncated())
}

var _ acidns.Exchanger = (*stubExchanger)(nil)
