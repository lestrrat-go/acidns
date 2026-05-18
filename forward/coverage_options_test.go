package forward_test

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/forward"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// slowUpstream returns Exchange responses only after release is closed,
// so a test can saturate the forwarder's inflight slots deterministically.
type slowUpstream struct {
	release     chan struct{}
	entered     chan struct{}
	enteredOnce sync.Once
	releaseOnce sync.Once
}

// Release unblocks any goroutines currently waiting on this upstream.
// Safe to call multiple times.
func (s *slowUpstream) Release() {
	s.releaseOnce.Do(func() { close(s.release) })
}

func (s *slowUpstream) Exchange(ctx context.Context, q wire.Message) (wire.Message, error) {
	s.enteredOnce.Do(func() { close(s.entered) })
	select {
	case <-s.release:
	case <-ctx.Done():
		return wire.Message{}, ctx.Err()
	}
	ar, _ := rdata.NewA(netip.MustParseAddr("203.0.113.99"))
	resp, _ := wire.NewMessageBuilder().
		ID(q.ID()).
		Response(true).
		Question(q.Questions()[0]).
		Answer(wire.NewRecord(q.Questions()[0].Name(), time.Minute, ar)).
		Build()
	return resp, nil
}

type capturingWriter struct {
	src     netip.AddrPort
	written wire.Message
}

func (c *capturingWriter) WriteMsg(m wire.Message) error { c.written = m; return nil }
func (capturingWriter) Network() string                  { return "udp" }
func (capturingWriter) LocalAddr() netip.AddrPort        { return netip.AddrPort{} }
func (c capturingWriter) RemoteAddr() netip.AddrPort     { return c.src }

// TestForwardMaxInflightSaturatesReturnsErrInflightFull pins the
// fail-fast contract: with maxInflight=1 and a single in-flight slow
// query, additional *distinct* cache-miss queries must observe the
// inflight cap and yield ErrInflightFull at the upstream layer (the
// forwarder then maps that to a SERVFAIL response).
func TestForwardMaxInflightSaturatesReturnsErrInflightFull(t *testing.T) {
	t.Parallel()
	up := &slowUpstream{release: make(chan struct{}), entered: make(chan struct{})}
	t.Cleanup(up.Release)

	h, err := forward.New(up,
		forward.WithMaxInflight(1),
	)
	require.NoError(t, err)

	mkQuery := func(qname string) wire.Message {
		q, err := wire.NewMessageBuilder().
			ID(1).
			RecursionDesired(true).
			Question(wire.NewQuestion(wire.MustParseName(qname), rrtype.A)).
			Build()
		require.NoError(t, err)
		return q
	}

	// First query occupies the slot and blocks until release.
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		w := &capturingWriter{src: netip.MustParseAddrPort("198.51.100.1:1")}
		h.ServeDNS(t.Context(), w, mkQuery("a.example."))
	}()

	// Wait for the upstream to actually be in-flight before issuing
	// the second query — otherwise we race the semaphore acquisition.
	select {
	case <-up.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not enter Exchange within deadline")
	}

	// Second query, *different* qname → distinct singleflight key →
	// hits the saturated semaphore → ErrInflightFull → SERVFAIL.
	w2 := &capturingWriter{src: netip.MustParseAddrPort("198.51.100.2:1")}
	h.ServeDNS(t.Context(), w2, mkQuery("b.example."))
	require.Equal(t, wire.RCODEServFail, w2.written.Flags().RCODE(),
		"saturated forward.WithMaxInflight cap must surface as SERVFAIL on the inbound writer")

	// Release the slow upstream so the first goroutine exits.
	up.Release()
	<-firstDone
}

// TestForwardAllowNoRDDefaultsToRefused pins the secure-default
// behaviour: a forwarder with no WithAllowNoRD opts refuses (RCODE
// REFUSED) queries whose RD bit is clear, because answering them from
// cache is an open-resolver-style amplification primitive.
func TestForwardAllowNoRDDefaultsToRefused(t *testing.T) {
	t.Parallel()
	h, err := forward.New(&slowUpstream{release: make(chan struct{}), entered: make(chan struct{})})
	require.NoError(t, err)
	q, err := wire.NewMessageBuilder().
		ID(1).
		// RD bit deliberately NOT set.
		Question(wire.NewQuestion(wire.MustParseName("example."), rrtype.A)).
		Build()
	require.NoError(t, err)
	w := &capturingWriter{src: netip.MustParseAddrPort("198.51.100.5:1")}
	h.ServeDNS(t.Context(), w, q)
	require.Equal(t, wire.RCODERefused, w.written.Flags().RCODE(),
		"RD=0 query must be REFUSED by default")
}

// TestForwardAllowNoRDTrueAllowsRDClearQueries proves the toggle. An
// operator-supplied WithAllowNoRD(true) makes the forwarder serve
// RD=0 queries from cache instead of refusing them; we verify by
// observing that the upstream is reached.
func TestForwardAllowNoRDTrueAllowsRDClearQueries(t *testing.T) {
	t.Parallel()
	up := &slowUpstream{release: make(chan struct{}), entered: make(chan struct{})}
	up.Release() // never block — let queries through

	h, err := forward.New(up,
		forward.WithAllowNoRD(true),
	)
	require.NoError(t, err)

	q, err := wire.NewMessageBuilder().
		ID(2).
		Question(wire.NewQuestion(wire.MustParseName("example."), rrtype.A)).
		Build()
	require.NoError(t, err)
	w := &capturingWriter{src: netip.MustParseAddrPort("198.51.100.5:1")}
	h.ServeDNS(t.Context(), w, q)

	require.Equal(t, wire.RCODENoError, w.written.Flags().RCODE(),
		"WithAllowNoRD(true) must serve RD=0 queries (not REFUSE)")
	require.NotEmpty(t, w.written.Answers(), "the upstream's answer should make it through")
}
