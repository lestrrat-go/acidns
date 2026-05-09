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
// histograms without further classification. Envelopes reports how
// many WriteMsg calls the inner handler made: 0 = dropped, 1 =
// single response, >1 = streamed (e.g. AXFR/IXFR).
//
// Err is the error returned by the FIRST WriteMsg call, if any.
//
// # Cardinality
//
// Request and Response carry the full message (including QNAME) so
// observers can extract whatever they need. A naive observer that
// emits QNAME as a Prometheus label or trace tag will produce
// unbounded label cardinality (one series per unique name queried).
// At server-grade traffic this is a memory and storage outage in
// every metrics backend the authors of this library are familiar
// with. Aggregate or hash QNAME to a small bounded category before
// labelling; only emit the raw QNAME on a sampled path or to a
// trace-only sink.
//
// # Panics
//
// If the inner handler panics, the observer is NOT called — the
// Server framework's no-recover policy lets the panic propagate to
// the listener (and from there typically to the process). Observers
// are therefore not a reliable signal for handler crashes; use a
// process-level supervisor instead.
type QueryEvent struct {
	request    wire.Message
	response   wire.Message
	remoteAddr netip.AddrPort
	localAddr  netip.AddrPort
	network    string
	latency    time.Duration
	envelopes  int
	err        error
}

// Request returns the inbound request message.
func (e QueryEvent) Request() wire.Message { return e.request }

// Response returns the captured response message; nil for dropped or
// streamed exchanges. See QueryEvent for the precise semantics.
func (e QueryEvent) Response() wire.Message { return e.response }

// RemoteAddr returns the client's address.
func (e QueryEvent) RemoteAddr() netip.AddrPort { return e.remoteAddr }

// LocalAddr returns the server-side address that handled the query.
func (e QueryEvent) LocalAddr() netip.AddrPort { return e.localAddr }

// Network returns the listener network ("udp", "tcp", etc.).
func (e QueryEvent) Network() string { return e.network }

// Latency returns the time spent inside the inner handler.
func (e QueryEvent) Latency() time.Duration { return e.latency }

// Envelopes returns the number of WriteMsg calls made by the inner
// handler (0 = dropped, 1 = single response, >1 = streamed).
func (e QueryEvent) Envelopes() int { return e.envelopes }

// Err returns the error returned by the FIRST WriteMsg call, if any.
func (e QueryEvent) Err() error { return e.err }

// QueryEventBuilder builds a QueryEvent.
type QueryEventBuilder struct {
	e QueryEvent
}

// NewQueryEventBuilder returns a fresh QueryEventBuilder.
func NewQueryEventBuilder() *QueryEventBuilder { return &QueryEventBuilder{} }

// Request sets the inbound request message.
func (b *QueryEventBuilder) Request(v wire.Message) *QueryEventBuilder { b.e.request = v; return b }

// Response sets the captured response.
func (b *QueryEventBuilder) Response(v wire.Message) *QueryEventBuilder {
	b.e.response = v
	return b
}

// RemoteAddr sets the client address.
func (b *QueryEventBuilder) RemoteAddr(v netip.AddrPort) *QueryEventBuilder {
	b.e.remoteAddr = v
	return b
}

// LocalAddr sets the server address.
func (b *QueryEventBuilder) LocalAddr(v netip.AddrPort) *QueryEventBuilder {
	b.e.localAddr = v
	return b
}

// Network sets the listener network identifier.
func (b *QueryEventBuilder) Network(v string) *QueryEventBuilder { b.e.network = v; return b }

// Latency sets the measured inner-handler latency.
func (b *QueryEventBuilder) Latency(v time.Duration) *QueryEventBuilder {
	b.e.latency = v
	return b
}

// Envelopes sets the WriteMsg envelope count.
func (b *QueryEventBuilder) Envelopes(v int) *QueryEventBuilder { b.e.envelopes = v; return b }

// Err sets the first WriteMsg error, if any.
func (b *QueryEventBuilder) Err(v error) *QueryEventBuilder { b.e.err = v; return b }

// Build returns the assembled QueryEvent.
func (b *QueryEventBuilder) Build() (QueryEvent, error) {
	return b.e, nil
}

// QueryObserver receives one [QueryEvent] per Handler invocation. It
// runs synchronously on the request goroutine; an observer that does
// expensive work (e.g. writes to a remote tracing endpoint) MUST
// dispatch that work to a worker goroutine of its own. A common
// pattern is to send the event into a buffered channel and process
// the channel from a worker pool. See QueryEvent's "Cardinality"
// note before deriving metric labels from message contents.
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
	ev, _ := NewQueryEventBuilder().
		Request(q).
		Response(captured.snapshot()).
		RemoteAddr(w.RemoteAddr()).
		LocalAddr(w.LocalAddr()).
		Network(w.Network()).
		Latency(time.Since(started)).
		Envelopes(captured.envelopeCount()).
		Err(captured.firstErr()).
		Build()
	o.obs(ev)
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
		return wire.Message{}
	}
	return c.first
}

func (c *capturingWriter) firstErr() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.firstE
}

func (c *capturingWriter) envelopeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.wrote
}
