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

	"github.com/lestrrat-go/acidns/wire"
)

// ErrServerClosed is recorded on the Controller after the server's
// accept loop exits because ctx was cancelled or the listener was
// closed for an expected reason. It is NOT returned from Run itself —
// Run only returns errors that happened during socket bind.
var ErrServerClosed = errors.New("dnsserver: server closed")

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

// controllerCore is the shared runtime state behind every concrete
// per-protocol Controller. Embedded by value so the public types
// promote Addr / Done / Err / setErr without re-declaring them.
//
// Each protocol gets its own Controller type ([UDPController],
// [TCPController]) so protocol-specific runtime queries — e.g.
// "current TCP connections", "UDP packets dropped at the inflight
// semaphore" — can be added without polluting the shape of the
// other protocols' handles. Today the public types are equivalent;
// the split exists for forward-compatibility, not present need.
type controllerCore struct {
	addr netip.AddrPort
	done chan struct{}
	err  atomic.Pointer[error]
}

func newCore(addr netip.AddrPort) controllerCore {
	return controllerCore{addr: addr, done: make(chan struct{})}
}

// Addr returns the address the server is bound to. When the caller
// asked for port 0, this reflects the kernel-assigned ephemeral port.
func (c *controllerCore) Addr() netip.AddrPort { return c.addr }

// Done returns a channel that is closed when the server's work
// goroutine has fully exited (in-flight handlers drained, listening
// socket closed). Wait on this in tests or in process shutdown.
func (c *controllerCore) Done() <-chan struct{} { return c.done }

// Err returns the error that terminated the work goroutine. Returns
// nil before Done is closed and after a clean shutdown via context
// cancellation. Non-nil only when an unexpected condition (e.g. an
// Accept failure outside the recoverable set) ended the loop.
//
// Note: Err does NOT surface Handler panics. The Server framework
// has no `recover()` around handler dispatch (by design — see the
// [Handler] doc); a panicking handler propagates up to the listener
// goroutine and crashes the process before the work loop exits.
// Use a process-level supervisor for crash detection.
func (c *controllerCore) Err() error {
	if p := c.err.Load(); p != nil {
		return *p
	}
	return nil
}

// Wait blocks until the server's work goroutine has exited and
// returns its terminal error. It is equivalent to:
//
//	<-c.Done()
//	return c.Err()
//
// and is provided as a convenience for the common "start the server,
// wait for it to finish, check why it exited" call shape:
//
//	ctrl, err := srv.Run(ctx)
//	if err != nil {
//	    return err
//	}
//	return ctrl.Wait()
//
// For composing with other channels (e.g. waiting on multiple
// controllers via select) use [controllerCore.Done] directly.
func (c *controllerCore) Wait() error {
	<-c.done
	return c.Err()
}

func (c *controllerCore) setErr(err error) {
	if err != nil {
		c.err.Store(&err)
	}
}

// UDPController is the runtime handle returned by [UDPServer.Run].
// It is the only path to the running UDP server instance: cancelling
// the ctx passed to Run is the only way to stop the instance, and
// Done() / Err() / Addr() are the only public observations.
//
// Future protocol-specific runtime queries (e.g. inflight-handler
// count, packets dropped at the semaphore) belong on this type.
type UDPController struct {
	controllerCore
}

// TCPController is the runtime handle returned by [TCPServer.Run].
// It is the only path to the running TCP server instance: cancelling
// the ctx passed to Run is the only way to stop the instance, and
// Done() / Err() / Addr() are the only public observations.
//
// Future protocol-specific runtime queries (e.g. open-connection
// count, queries-in-flight per connection) belong on this type.
type TCPController struct {
	controllerCore
}
