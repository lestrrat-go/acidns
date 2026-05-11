package acidns

// Server framework: a Handler-based DNS server modelled on the net/http style.
// Handlers receive a parsed Message and a ResponseWriter; concrete servers
// (UDP, TCP) bind sockets and dispatch.
//
// The framework itself does no policy: it does not implement zones,
// recursion, caching, or rate limiting. Those live in sub-packages
// (authoritative, recursive, forward, ...) that implement Handler and may be
// composed via standard middleware patterns.
//
// # Lifecycle
//
// Servers start with [UDPServer.Run] / [TCPServer.Run]:
//
//	srv, err := acidns.NewUDPServer(addr, handler)
//	ctrl, err := srv.Run(ctx)
//	// ctrl.Addr() is the bound address (useful with port=0)
//	<-ctrl.Done() // optional: wait for clean exit
//	if err := ctrl.Err(); err != nil { ... }
//
// Run binds the socket synchronously, spawns the accept-and-dispatch
// goroutine, and returns immediately. The goroutine exits when ctx is
// cancelled; cancellation is the ONLY way to stop the server. There is
// no Shutdown method — keeping the lifecycle in ctx eliminates the
// "is the ctx the right one?" footgun and the start-while-stopping
// race-condition surface.

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"

	"github.com/lestrrat-go/acidns/internal/serverctl"
	"github.com/lestrrat-go/acidns/wire"
)

// ErrServerClosed is recorded on the Controller after the server's
// accept loop exits because ctx was cancelled or the listener was
// closed for an expected reason. It is NOT returned from Run itself —
// Run only returns errors that happened during socket bind.
//
// The transport sub-packages ([dot], [doh], [doq], [dnscrypt]) re-export
// this sentinel under their own package's ErrServerClosed so
// errors.Is(err, dot.ErrServerClosed) and errors.Is(err,
// acidns.ErrServerClosed) both match the same closed-server error.
var ErrServerClosed = errors.New("acidns: server closed")

// ErrInflightFull is the canonical sentinel for "max inflight upstream
// calls reached" returned by the [forward] and [recursive] caching
// layers. The sub-packages re-export this value so a caller that does
// errors.Is(err, acidns.ErrInflightFull) matches both layers.
var ErrInflightFull = errors.New("acidns: max inflight upstream calls reached")

// ErrInvalidAddress is returned by exchanger and server constructors
// when the supplied netip.AddrPort is the zero value or otherwise
// fails IsValid. Wrapped via %w so callers can match it with
// errors.Is.
var ErrInvalidAddress = errors.New("acidns: invalid address")

// ErrNilHandler is returned by [NewUDPServer] / [NewTCPServer] and
// the public-server / middleware constructors when a required
// [Handler] argument is nil.
var ErrNilHandler = errors.New("acidns: handler is nil")

// Handler is the interface implemented by anything that answers DNS queries.
//
// # Panics
//
// A Handler MUST NOT panic during normal operation. The Server framework
// does NOT install a recover() around handler dispatch — by design, so
// the operator can choose its policy (process restart, structured log,
// crash-loop detector) without the library laundering panics into
// SERVFAILs that mask the underlying bug. If your handler chain may
// panic and you want it converted into a response, wrap the chain in a
// middleware of your own that calls recover().
type Handler interface {
	ServeDNS(ctx context.Context, w ResponseWriter, q wire.Message)
}

// HandlerFunc adapts a plain function into a Handler.
type HandlerFunc func(ctx context.Context, w ResponseWriter, q wire.Message)

// ServeDNS calls f.
func (f HandlerFunc) ServeDNS(ctx context.Context, w ResponseWriter, q wire.Message) {
	f(ctx, w, q)
}

// ResponseWriter is the channel a Handler uses to emit its response.
//
// WriteMsg may serialise the message multiple times (e.g. when a UDP
// response would exceed the negotiated payload size, the writer rebuilds
// the message with the TC bit set and an empty body). Handlers SHOULD NOT
// hold a ResponseWriter past the call to ServeDNS.
//
// Network reports the underlying transport ("udp", "tcp", "dot", "doh") so
// handlers can refuse stream-only operations (e.g. AXFR) over datagrams.
type ResponseWriter interface {
	WriteMsg(m wire.Message) error
	RemoteAddr() netip.AddrPort
	LocalAddr() netip.AddrPort
	Network() string
}

// echoOPT attaches an OPT pseudo-RR to b when q carried EDNS, so an
// EDNS-aware client receives a response with EDNS support intact. RFC
// 6891 §6.1.1 requires servers that understand EDNS to return an OPT
// even on error responses; without it, EDNS-aware clients downgrade
// on subsequent queries. Used by middleware refuse paths (ACL,
// rate-limit) where the request is rejected without reaching the
// inner handler.
func echoOPT(b *wire.MessageBuilder, q wire.Message) *wire.MessageBuilder {
	qe, ok := q.EDNS()
	if !ok {
		return b
	}
	ed, err := wire.NewEDNSBuilder().
		UDPSize(1232). // DNS Flag Day 2020 default
		DO(qe.DO()).
		Build()
	if err != nil {
		return b
	}
	return b.EDNS(ed)
}

// UDPController is the runtime handle returned by [UDPServer.Run].
// It is the only path to the running UDP server instance: cancelling
// the ctx passed to Run is the only way to stop the instance, and
// Done() / Err() / Addr() and the metric accessors are the only
// public observations.
type UDPController struct {
	serverctl.Core

	parseDrops     atomic.Uint64
	inflightDrops  atomic.Uint64
	preFilterDrops atomic.Uint64
	preflightDrops atomic.Uint64
}

// PacketsDroppedParseError returns the cumulative count of inbound
// UDP datagrams that failed [wire.Unmarshal]. Under attack a sudden
// rise here is the canonical "someone is throwing garbage at the
// listener" signal; under normal operation the number stays at 0
// modulo the occasional ICMP-driven mangled datagram.
func (c *UDPController) PacketsDroppedParseError() uint64 { return c.parseDrops.Load() }

// PacketsDroppedAtSemaphore returns the cumulative count of inbound
// datagrams refused at the [WithUDPListenerMaxInflight] cap. Steady growth
// means the listener is pinned at its concurrency bound — either the
// handler is slow, the workload is too large for the configured
// inflight cap, or the listener is being flooded.
func (c *UDPController) PacketsDroppedAtSemaphore() uint64 { return c.inflightDrops.Load() }

// PacketsDroppedByPreFilter returns the cumulative count of datagrams
// rejected by the [WithUDPListenerPreParseFilter] gate. Useful to measure
// the effectiveness of an operator's source-prefix denylist.
func (c *UDPController) PacketsDroppedByPreFilter() uint64 { return c.preFilterDrops.Load() }

// PacketsDroppedByPreflight returns the cumulative count of inbound
// datagrams parsed successfully but rejected by [PreflightRequest]
// (chiefly QR=1 spoofed responses, malformed opcodes, or zero-question
// queries). Steady growth here is the canonical "someone is firing
// spoofed responses at the listener" signal — the most common
// reflection-attack participation primitive — and is invisible at the
// parseDrops counter because the wire format is well-formed.
func (c *UDPController) PacketsDroppedByPreflight() uint64 { return c.preflightDrops.Load() }

// TCPController is the runtime handle returned by [TCPServer.Run].
// It is the only path to the running TCP server instance: cancelling
// the ctx passed to Run is the only way to stop the instance, and
// Done() / Err() / Addr() are the only public observations.
//
// Future protocol-specific runtime queries (e.g. open-connection
// count, queries-in-flight per connection) belong on this type.
type TCPController struct {
	serverctl.Core
}
