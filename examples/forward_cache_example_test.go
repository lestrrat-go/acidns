package examples_test

import (
	"context"
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/lestrrat-go/acidns/forward"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// stubUpstream is a minimal acidns.Exchanger that hands out a fixed A
// record and counts how many times it was hit.
type stubUpstream struct {
	calls atomic.Int64
}

func (s *stubUpstream) Exchange(_ context.Context, q wire.Message) (wire.Message, error) {
	s.calls.Add(1)
	resp, _ := wire.NewBuilder().
		ID(q.ID()).
		Response(true).
		RecursionAvailable(true).
		Question(q.Questions()[0]).
		Answer(wire.NewRecord(q.Questions()[0].Name(), time.Minute,
			rdata.MustNewA(netip.MustParseAddr("198.51.100.42")))).
		Build()
	return resp, nil
}

// captureWriter is a minimal acidns.ResponseWriter for in-process
// Handler invocation.
type forwardCaptureWriter struct{ got wire.Message }

func (c *forwardCaptureWriter) WriteMsg(m wire.Message) error { c.got = m; return nil }
func (c *forwardCaptureWriter) RemoteAddr() netip.AddrPort    { return netip.AddrPort{} }
func (c *forwardCaptureWriter) LocalAddr() netip.AddrPort     { return netip.AddrPort{} }
func (c *forwardCaptureWriter) Network() string               { return "udp" }

func Example_forward_cache() {
	// Wire a forward.Handler over a stub upstream so the example is
	// fully in-process. The first query is forwarded; the second is a
	// cache hit, evidenced by the upstream call counter staying at 1.
	upstream := &stubUpstream{}
	h, err := forward.New(forward.WithUpstream(upstream))
	if err != nil {
		fmt.Println("forward:", err)
		return
	}

	q, _ := wire.NewBuilder().
		ID(0xabcd).
		RecursionDesired(true).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()

	for range 2 {
		w := &forwardCaptureWriter{}
		h.ServeDNS(context.Background(), w, q)
		a, _ := wire.RDataAs[rdata.A](w.got.Answers()[0])
		fmt.Println("answer:", a.Addr())
	}

	fmt.Println("upstream calls:", upstream.calls.Load())
	fmt.Println("cache size:", h.CacheSize())

	// OUTPUT:
	// answer: 198.51.100.42
	// answer: 198.51.100.42
	// upstream calls: 1
	// cache size: 1
}
