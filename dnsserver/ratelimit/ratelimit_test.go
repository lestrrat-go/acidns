package ratelimit_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/lestrrat-go/acidns/dnsserver"
	"github.com/lestrrat-go/acidns/dnsserver/ratelimit"
	"github.com/stretchr/testify/require"
)

type fakeWriter struct {
	src      netip.AddrPort
	captured dnsmsg.Message
	written  bool
}

func (w *fakeWriter) WriteMsg(m dnsmsg.Message) error {
	w.captured = m
	w.written = true
	return nil
}
func (w *fakeWriter) RemoteAddr() netip.AddrPort { return w.src }
func (w *fakeWriter) LocalAddr() netip.AddrPort  { return netip.AddrPort{} }
func (w *fakeWriter) Network() string            { return "udp" }

func mkInner() dnsserver.Handler {
	return dnsserver.HandlerFunc(func(_ context.Context, w dnsserver.ResponseWriter, q dnsmsg.Message) {
		ans := dnsmsg.NewRecord(q.Questions()[0].Name(), time.Minute,
			rdata.NewA(netip.MustParseAddr("203.0.113.1")))
		resp, _ := dnsmsg.NewBuilder().
			ID(q.ID()).
			Response(true).
			Question(q.Questions()[0]).
			Answer(ans).
			Build()
		_ = w.WriteMsg(resp)
	})
}

func mkQuery(t *testing.T) dnsmsg.Message {
	t.Helper()
	q, err := dnsmsg.NewBuilder().
		ID(1).
		Question(dnsmsg.NewQuestion(dnsname.MustParse("example.com"), rrtype.A)).
		Build()
	require.NoError(t, err)
	return q
}

func TestRateLimitBurstThenRefuse(t *testing.T) {
	t.Parallel()

	h := ratelimit.New(mkInner(),
		ratelimit.WithQPS(0.0001), // refill almost never within the test
		ratelimit.WithBurst(3),
	)

	for i := 0; i < 3; i++ {
		w := &fakeWriter{src: netip.MustParseAddrPort("198.51.100.5:1000")}
		h.ServeDNS(context.Background(), w, mkQuery(t))
		require.Equal(t, dnsmsg.RCODENoError, w.captured.Flags().RCODE(),
			"first %d should pass through", i+1)
	}

	w := &fakeWriter{src: netip.MustParseAddrPort("198.51.100.5:1000")}
	h.ServeDNS(context.Background(), w, mkQuery(t))
	require.Equal(t, dnsmsg.RCODERefused, w.captured.Flags().RCODE())
}

func TestRateLimitPerSourceIndependent(t *testing.T) {
	t.Parallel()
	h := ratelimit.New(mkInner(), ratelimit.WithQPS(0.0001), ratelimit.WithBurst(1))

	w1 := &fakeWriter{src: netip.MustParseAddrPort("203.0.113.1:1")}
	h.ServeDNS(context.Background(), w1, mkQuery(t))
	require.Equal(t, dnsmsg.RCODENoError, w1.captured.Flags().RCODE())

	// First query from a different source must succeed regardless of the
	// other's exhausted bucket.
	w2 := &fakeWriter{src: netip.MustParseAddrPort("203.0.113.2:1")}
	h.ServeDNS(context.Background(), w2, mkQuery(t))
	require.Equal(t, dnsmsg.RCODENoError, w2.captured.Flags().RCODE())
}

func TestRateLimitDrop(t *testing.T) {
	t.Parallel()
	h := ratelimit.New(mkInner(),
		ratelimit.WithQPS(0.0001), ratelimit.WithBurst(1), ratelimit.WithDrop())

	w := &fakeWriter{src: netip.MustParseAddrPort("203.0.113.10:1")}
	h.ServeDNS(context.Background(), w, mkQuery(t)) // first OK
	require.True(t, w.written)

	w2 := &fakeWriter{src: netip.MustParseAddrPort("203.0.113.10:1")}
	h.ServeDNS(context.Background(), w2, mkQuery(t)) // second dropped
	require.False(t, w2.written, "drop mode must not write a response")
}

func TestRateLimitGroupPrefix(t *testing.T) {
	t.Parallel()
	// /24 grouping means 198.51.100.1 and 198.51.100.2 share a bucket.
	h := ratelimit.New(mkInner(),
		ratelimit.WithQPS(0.0001),
		ratelimit.WithBurst(1),
		ratelimit.WithGroupPrefix(24),
	)

	w1 := &fakeWriter{src: netip.MustParseAddrPort("198.51.100.1:1")}
	h.ServeDNS(context.Background(), w1, mkQuery(t))
	require.Equal(t, dnsmsg.RCODENoError, w1.captured.Flags().RCODE())

	w2 := &fakeWriter{src: netip.MustParseAddrPort("198.51.100.2:1")}
	h.ServeDNS(context.Background(), w2, mkQuery(t))
	require.Equal(t, dnsmsg.RCODERefused, w2.captured.Flags().RCODE(),
		"second source in same /24 should share the exhausted bucket")
}

func TestRateLimitRefillOverTime(t *testing.T) {
	t.Parallel()
	h := ratelimit.New(mkInner(),
		ratelimit.WithQPS(50),
		ratelimit.WithBurst(1),
	)

	w1 := &fakeWriter{src: netip.MustParseAddrPort("203.0.113.20:1")}
	h.ServeDNS(context.Background(), w1, mkQuery(t)) // burst
	require.Equal(t, dnsmsg.RCODENoError, w1.captured.Flags().RCODE())

	w2 := &fakeWriter{src: netip.MustParseAddrPort("203.0.113.20:1")}
	h.ServeDNS(context.Background(), w2, mkQuery(t)) // immediately after
	require.Equal(t, dnsmsg.RCODERefused, w2.captured.Flags().RCODE())

	time.Sleep(40 * time.Millisecond) // 50qps → 2 tokens accumulated

	w3 := &fakeWriter{src: netip.MustParseAddrPort("203.0.113.20:1")}
	h.ServeDNS(context.Background(), w3, mkQuery(t))
	require.Equal(t, dnsmsg.RCODENoError, w3.captured.Flags().RCODE(),
		"after refill the bucket should permit again")
}
