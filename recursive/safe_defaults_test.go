package recursive_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/recursive"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// noopWriter captures the response without touching a socket.
type noopWriter struct {
	resp wire.Message
}

func (w *noopWriter) WriteMsg(m wire.Message) error { w.resp = m; return nil }
func (w *noopWriter) RemoteAddr() netip.AddrPort    { return netip.AddrPort{} }
func (w *noopWriter) LocalAddr() netip.AddrPort     { return netip.AddrPort{} }
func (w *noopWriter) Network() string               { return "udp" }

// TestServeDNSRefusedWithoutRD verifies the safe default: a recursive
// resolver returns REFUSED to a query without the RD bit, refusing to
// act as an open-resolver amplification primitive.
func TestServeDNSRefusedWithoutRD(t *testing.T) {
	t.Parallel()
	r := mustRecursive(t, recursive.WithRoots(netip.MustParseAddrPort("127.0.0.1:1")))
	q, err := wire.NewBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("a.test."), rrtype.A)).
		Build()
	require.NoError(t, err)
	w := &noopWriter{}
	r.ServeDNS(context.Background(), w, q)
	require.NotNil(t, w.resp)
	require.Equal(t, wire.RCODERefused, w.resp.Flags().RCODE())
}

// TestServeDNSAllowNoRDOptIn verifies WithAllowNoRD restores the
// pre-default behaviour where the resolver accepts RD=0 queries.
// We don't care about the actual answer (the iteration will fail),
// only that REFUSED is no longer the response.
func TestServeDNSAllowNoRDOptIn(t *testing.T) {
	t.Parallel()
	r := mustRecursive(t,
		recursive.WithRoots(netip.MustParseAddrPort("127.0.0.1:1")),
		recursive.WithMaxIterations(1),
		recursive.WithAllowNoRD(),
	)
	q, err := wire.NewBuilder().
		ID(2).
		Question(wire.NewQuestion(wire.MustParseName("a.test."), rrtype.A)).
		Build()
	require.NoError(t, err)
	w := &noopWriter{}
	r.ServeDNS(context.Background(), w, q)
	require.NotNil(t, w.resp)
	require.NotEqual(t, wire.RCODERefused, w.resp.Flags().RCODE(),
		"WithAllowNoRD must let RD=0 queries reach the resolver")
}

var _ acidns.Handler = (*recursive.Recursive)(nil) // compile-time check that *Recursive implements acidns.Handler
