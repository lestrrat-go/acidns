package dnsclient_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient"
	"github.com/lestrrat-go/acidns/dnsclient/specialuse"
	"github.com/lestrrat-go/acidns/dnsclient/transport"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

func TestRCodeErrorIs(t *testing.T) {
	t.Parallel()
	live := &dnsclient.RCodeError{Code: wire.RCODENXDomain}
	require.True(t, errors.Is(live, dnsclient.ErrNXDOMAIN))
	require.False(t, errors.Is(live, dnsclient.ErrServFail))
	require.False(t, errors.Is(live, errors.New("other")))
	require.Equal(t, "dnsclient: NXDOMAIN", live.Error())
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
	r, err := dnsclient.New(dnsclient.WithExchanger(&stubExchanger{}))
	require.NoError(t, err)
	require.NotNil(t, r)
}

func TestNewRequiresSomething(t *testing.T) {
	t.Parallel()
	_, err := dnsclient.New()
	require.ErrorIs(t, err, dnsclient.ErrNoResolver)
}

func TestOptionAccessors(t *testing.T) {
	t.Parallel()
	// Just ensure each option compiles and applies without panic.
	_ = dnsclient.WithEDNSUDPSize(4096)
	_ = dnsclient.WithDNSSEC(true)
	_ = dnsclient.WithEDNS(false)
	_ = dnsclient.WithAttempts(3)
	_ = dnsclient.WithPerAttemptTimeout(time.Second)
	_ = dnsclient.WithSearchList(wire.MustParseName("example.com"))
	_ = dnsclient.WithNdots(2)
	_ = dnsclient.WithSpecialUse(false)
	_ = dnsclient.WithServers(netip.MustParseAddrPort("127.0.0.1:53"))
}

func TestAnswerMethods(t *testing.T) {
	t.Parallel()
	// Build a synthetic answer by exercising Resolve with a stub.
	q, err := wire.NewBuilder().
		ID(1).
		Response(true).
		Authoritative(true).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	require.NoError(t, err)
	stub := &stubExchanger{resp: q}
	r, err := dnsclient.New(dnsclient.WithExchanger(stub), dnsclient.WithSpecialUse(false))
	require.NoError(t, err)
	ans, err := r.Resolve(context.Background(), wire.MustParseName("example.com"), rrtype.A)
	require.NoError(t, err)
	require.NotNil(t, ans.Question())
	require.NotNil(t, ans.Raw())
	require.True(t, ans.Authoritative())
	require.False(t, ans.Truncated())
}

var _ transport.Exchanger = (*stubExchanger)(nil)
