package acidns_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

type fakeWriter struct {
	src      netip.AddrPort
	captured wire.Message
}

func (w *fakeWriter) WriteMsg(m wire.Message) error { w.captured = m; return nil }
func (w *fakeWriter) RemoteAddr() netip.AddrPort    { return w.src }
func (w *fakeWriter) LocalAddr() netip.AddrPort     { return netip.AddrPort{} }
func (w *fakeWriter) Network() string               { return "udp" }

func aclMkInner() acidns.Handler {
	return acidns.HandlerFunc(func(_ context.Context, w acidns.ResponseWriter, q wire.Message) {
		ans := wire.NewRecord(q.Questions()[0].Name(), time.Minute,
			rdata.MustNewA(netip.MustParseAddr("203.0.113.1")))
		resp, _ := wire.NewBuilder().
			ID(q.ID()).
			Response(true).
			Question(q.Questions()[0]).
			Answer(ans).
			Build()
		_ = w.WriteMsg(resp)
	})
}

func aclMkQuery(t *testing.T) wire.Message {
	t.Helper()
	q, err := wire.NewBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	require.NoError(t, err)
	return q
}

func TestAllowList(t *testing.T) {
	t.Parallel()
	h := acidns.NewACL(aclMkInner(), acidns.WithACLAllow(netip.MustParsePrefix("127.0.0.0/8")))

	w1 := &fakeWriter{src: netip.MustParseAddrPort("127.0.0.1:12345")}
	h.ServeDNS(context.Background(), w1, aclMkQuery(t))
	require.Equal(t, wire.RCODENoError, w1.captured.Flags().RCODE())

	w2 := &fakeWriter{src: netip.MustParseAddrPort("8.8.8.8:53")}
	h.ServeDNS(context.Background(), w2, aclMkQuery(t))
	require.Equal(t, wire.RCODERefused, w2.captured.Flags().RCODE())
}

func TestDenyList(t *testing.T) {
	t.Parallel()
	h := acidns.NewACL(aclMkInner(), acidns.WithACLDeny(netip.MustParsePrefix("192.168.0.0/16")))

	w1 := &fakeWriter{src: netip.MustParseAddrPort("192.168.1.5:1000")}
	h.ServeDNS(context.Background(), w1, aclMkQuery(t))
	require.Equal(t, wire.RCODERefused, w1.captured.Flags().RCODE())

	w2 := &fakeWriter{src: netip.MustParseAddrPort("10.0.0.5:1000")}
	h.ServeDNS(context.Background(), w2, aclMkQuery(t))
	require.Equal(t, wire.RCODENoError, w2.captured.Flags().RCODE())
}

func TestDenyBeatsAllow(t *testing.T) {
	t.Parallel()
	h := acidns.NewACL(aclMkInner(),
		acidns.WithACLAllow(netip.MustParsePrefix("10.0.0.0/8")),
		acidns.WithACLDeny(netip.MustParsePrefix("10.1.0.0/16")),
	)

	w1 := &fakeWriter{src: netip.MustParseAddrPort("10.1.2.3:1")}
	h.ServeDNS(context.Background(), w1, aclMkQuery(t))
	require.Equal(t, wire.RCODERefused, w1.captured.Flags().RCODE())

	w2 := &fakeWriter{src: netip.MustParseAddrPort("10.2.0.1:1")}
	h.ServeDNS(context.Background(), w2, aclMkQuery(t))
	require.Equal(t, wire.RCODENoError, w2.captured.Flags().RCODE())
}

func TestNoConfigPermitsAll(t *testing.T) {
	t.Parallel()
	h := acidns.NewACL(aclMkInner())
	w := &fakeWriter{src: netip.MustParseAddrPort("8.8.8.8:53")}
	h.ServeDNS(context.Background(), w, aclMkQuery(t))
	require.Equal(t, wire.RCODENoError, w.captured.Flags().RCODE())
}
