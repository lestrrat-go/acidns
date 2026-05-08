package acidns_test

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

type recordingWriter struct {
	resp wire.Message
}

func (w *recordingWriter) WriteMsg(m wire.Message) error { w.resp = m; return nil }
func (*recordingWriter) RemoteAddr() netip.AddrPort {
	return netip.MustParseAddrPort("198.51.100.1:1")
}
func (*recordingWriter) LocalAddr() netip.AddrPort {
	return netip.MustParseAddrPort("127.0.0.1:53")
}
func (*recordingWriter) Network() string { return netUDP }

const netUDP = "udp"

func TestNewObservedCapturesEvent(t *testing.T) {
	t.Parallel()

	inner := acidns.HandlerFunc(func(_ context.Context, w acidns.ResponseWriter, q wire.Message) {
		ans := wire.NewRecord(q.Questions()[0].Name(), 30*time.Second,
			rdata.NewA(netip.MustParseAddr("203.0.113.7")))
		resp, _ := wire.NewBuilder().
			ID(q.ID()).
			Response(true).
			Question(q.Questions()[0]).
			Answer(ans).
			Build()
		_ = w.WriteMsg(resp)
	})

	var (
		mu  sync.Mutex
		got acidns.QueryEvent
	)
	wrapped := acidns.NewObserved(inner, func(e acidns.QueryEvent) {
		mu.Lock()
		got = e
		mu.Unlock()
	})

	q, err := wire.NewBuilder().
		ID(0xdead).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	require.NoError(t, err)

	w := &recordingWriter{}
	wrapped.ServeDNS(context.Background(), w, q)

	mu.Lock()
	defer mu.Unlock()
	require.NotNil(t, got.Request, "Request must be set")
	require.NotNil(t, got.Response, "Response must be captured for single-write handlers")
	require.Equal(t, uint16(0xdead), got.Response.ID())
	require.Equal(t, netip.MustParseAddrPort("198.51.100.1:1"), got.RemoteAddr)
	require.Equal(t, netUDP, got.Network)
	require.GreaterOrEqual(t, got.Latency, time.Duration(0))
	require.NoError(t, got.Err)
}

func TestNewObservedNilObsReturnsInner(t *testing.T) {
	t.Parallel()
	called := false
	inner := acidns.HandlerFunc(func(context.Context, acidns.ResponseWriter, wire.Message) {
		called = true
	})
	wrapped := acidns.NewObserved(inner, nil)

	q, err := wire.NewBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	require.NoError(t, err)
	wrapped.ServeDNS(context.Background(), &recordingWriter{}, q)
	require.True(t, called, "nil observer must still invoke inner handler")
}
