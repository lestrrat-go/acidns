package chaos_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/lestrrat-go/acidns/dnsserver"
	"github.com/lestrrat-go/acidns/chaos"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

type captureWriter struct {
	resp wire.Message
}

func (c *captureWriter) WriteMsg(m wire.Message) error {
	c.resp = m
	return nil
}
func (c *captureWriter) RemoteAddr() netip.AddrPort { return netip.AddrPort{} }
func (c *captureWriter) LocalAddr() netip.AddrPort  { return netip.AddrPort{} }
func (c *captureWriter) Network() string            { return "udp" }

func mustQuery(t *testing.T, name string, class rrtype.Class) wire.Message {
	t.Helper()
	q, err := wire.NewBuilder().
		ID(1).
		Question(wire.NewQuestionClass(wire.MustParseName(name), rrtype.TXT, class)).
		Build()
	require.NoError(t, err)
	return q
}

func TestChaosIDServer(t *testing.T) {
	t.Parallel()
	h := chaos.New(chaos.WithIdentifier("ns1.example.net"))
	w := &captureWriter{}
	h.ServeDNS(context.Background(), w, mustQuery(t, "id.server.", rrtype.ClassCH))

	require.NotNil(t, w.resp)
	require.True(t, w.resp.Flags().Response())
	require.True(t, w.resp.Flags().Authoritative())
	require.Len(t, w.resp.Answers(), 1)
	txt := w.resp.Answers()[0].RData().(rdata.TXT)
	require.Equal(t, []string{"ns1.example.net"}, txt.Strings())
}

func TestChaosHostnameBindAlias(t *testing.T) {
	t.Parallel()
	h := chaos.New(chaos.WithIdentifier("alpha"))
	w := &captureWriter{}
	h.ServeDNS(context.Background(), w, mustQuery(t, "hostname.bind.", rrtype.ClassCH))
	txt := w.resp.Answers()[0].RData().(rdata.TXT)
	require.Equal(t, []string{"alpha"}, txt.Strings())
}

func TestChaosVersion(t *testing.T) {
	t.Parallel()
	h := chaos.New(chaos.WithVersion("acidns/dev"))
	w := &captureWriter{}
	h.ServeDNS(context.Background(), w, mustQuery(t, "version.bind.", rrtype.ClassCH))
	txt := w.resp.Answers()[0].RData().(rdata.TXT)
	require.Equal(t, []string{"acidns/dev"}, txt.Strings())
}

func TestChaosDelegatesOnNonChaos(t *testing.T) {
	t.Parallel()
	delegated := false
	next := dnsserver.HandlerFunc(func(_ context.Context, w dnsserver.ResponseWriter, q wire.Message) {
		delegated = true
		resp, _ := wire.NewBuilder().ID(q.ID()).Response(true).Build()
		_ = w.WriteMsg(resp)
	})
	h := chaos.New(chaos.WithIdentifier("foo"), chaos.WithNext(next))
	w := &captureWriter{}
	h.ServeDNS(context.Background(), w, mustQuery(t, "example.com.", rrtype.ClassIN))
	require.True(t, delegated)
}

func TestChaosRefusesWithoutNext(t *testing.T) {
	t.Parallel()
	h := chaos.New(chaos.WithIdentifier("foo"))
	w := &captureWriter{}
	h.ServeDNS(context.Background(), w, mustQuery(t, "example.com.", rrtype.ClassIN))
	require.Equal(t, wire.RCODERefused, w.resp.Flags().RCODE())
}
