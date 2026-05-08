package acidns

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/lestrrat-go/acidns/wire"
)

// QueryEvent is the data passed to a [QueryObserver] for each request /
// response pair. Latency is measured from the moment the inner handler
// is invoked until it returns; it does not include time spent reading
// the request off the wire or writing the response back.
//
// Response is the message the inner handler wrote, or nil if the
// handler did not call WriteMsg before returning, did not call it
// successfully, or wrote multiple messages (e.g. AXFR). When Response
// is nil the observer should treat the exchange as either dropped or
// streamed — neither shape is suitable for naive latency / RCODE
// histograms without further classification.
//
// Err is the error returned by WriteMsg, if any.
type QueryEvent struct {
	Request    wire.Message
	Response   wire.Message
	RemoteAddr netip.AddrPort
	LocalAddr  netip.AddrPort
	Network    string
	Latency    time.Duration
	Err        error
}

// QueryObserver receives one [QueryEvent] per Handler invocation. It
// runs synchronously on the request goroutine; an observer that does
// expensive work (e.g. writes to a remote tracing endpoint) MUST
// dispatch that work to a worker goroutine of its own.
type QueryObserver func(QueryEvent)

// NewObserved wraps inner so that obs is invoked once after each
// ServeDNS call. The wrapper transparently captures the response
// written through the [ResponseWriter] (so the observer sees the
// outgoing message) without altering inner's view of the writer.
//
// A nil obs returns inner unchanged.
func NewObserved(inner Handler, obs QueryObserver) Handler {
	if obs == nil {
		return inner
	}
	return &observed{inner: inner, obs: obs}
}

type observed struct {
	inner Handler
	obs   QueryObserver
}

func (o *observed) ServeDNS(ctx context.Context, w ResponseWriter, q wire.Message) {
	captured := &capturingWriter{ResponseWriter: w}
	started := time.Now()
	o.inner.ServeDNS(ctx, captured, q)
	o.obs(QueryEvent{
		Request:    q,
		Response:   captured.snapshot(),
		RemoteAddr: w.RemoteAddr(),
		LocalAddr:  w.LocalAddr(),
		Network:    w.Network(),
		Latency:    time.Since(started),
		Err:        captured.firstErr(),
	})
}

// capturingWriter is a ResponseWriter that records the message handed
// to WriteMsg and any error returned, while still forwarding to the
// underlying writer. If WriteMsg is called more than once (e.g. an AXFR
// streamer flushing multiple envelopes), only the first message is
// captured — the observer's Response will be nil for streamed
// exchanges.
type capturingWriter struct {
	ResponseWriter

	mu      sync.Mutex
	wrote   int
	first   wire.Message
	firstE  error
	dropped bool
}

func (c *capturingWriter) WriteMsg(m wire.Message) error {
	err := c.ResponseWriter.WriteMsg(m)
	c.mu.Lock()
	c.wrote++
	if c.wrote == 1 {
		c.first = m
		c.firstE = err
	} else {
		c.dropped = true
	}
	c.mu.Unlock()
	return err
}

func (c *capturingWriter) snapshot() wire.Message {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dropped {
		return nil
	}
	return c.first
}

func (c *capturingWriter) firstErr() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.firstE
}
