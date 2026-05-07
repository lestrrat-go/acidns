// Package dnsserver provides a Handler-based DNS server framework modelled
// on the net/http style. Handlers receive a parsed Message and a
// ResponseWriter; concrete servers (UDP, TCP) bind sockets and dispatch.
//
// The framework itself does no policy: it does not implement zones,
// recursion, caching, or rate limiting. Those live in sub-packages
// (dnsserver/authoritative, dnsserver/recursive, dnsserver/cache, ...) that
// implement Handler and may be composed via standard middleware patterns.
package dnsserver

import (
	"context"
	"errors"
	"net/netip"

	"github.com/lestrrat-go/acidns/wire"
)

// ErrServerClosed is returned by Serve after Shutdown or context cancel.
var ErrServerClosed = errors.New("dnsserver: server closed")

// Handler is the interface implemented by anything that answers DNS queries.
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

// Server is a bound, ready-to-serve DNS listener. Serve blocks until the
// supplied context is cancelled or an unrecoverable error occurs.
type Server interface {
	Serve(ctx context.Context) error
	Addr() netip.AddrPort
}
