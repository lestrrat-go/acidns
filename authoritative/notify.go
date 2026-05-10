package authoritative

import (
	"context"
	"net/netip"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
)

// NotifySource carries identifying information about the peer that
// sent a NOTIFY. It supersedes the live ResponseWriter that earlier
// versions of this API passed to [NotifyHandler]: by the time a
// handler runs, the ACK has already been flushed and the request
// goroutine has returned, so a ResponseWriter would be unsafe to
// write through. Remote address, local address, and transport name
// are sufficient for the typical handler's needs (selecting an
// upstream to AXFR from based on the primary's source).
type NotifySource struct {
	remote  netip.AddrPort
	local   netip.AddrPort
	network string
}

// Remote is the address of the peer that sent the NOTIFY.
func (s NotifySource) Remote() netip.AddrPort { return s.remote }

// Local is the local address the NOTIFY was received on.
func (s NotifySource) Local() netip.AddrPort { return s.local }

// Network is the underlying transport name ("udp", "tcp", "dot",
// "doh", "doq").
func (s NotifySource) Network() string { return s.network }

// NotifyHandler is invoked once per RFC 1996 NOTIFY received for a zone
// that this server holds. The default behaviour is to ACK the NOTIFY
// without further action; a non-nil handler is run after the ACK is
// queued (the response is sent regardless of whether the handler errs).
//
// The handler is invoked on a fresh goroutine bounded by the
// authoritative server's notify-concurrency cap (see
// [WithMaxNotifyInflight]). The typical handler schedules an
// IXFR/AXFR fetch from a primary, which can block on network I/O;
// running it on the request goroutine would pin the transport's
// per-handler concurrency slot for the duration of the fetch and let
// a single NOTIFY stall unrelated queries on the same listener.
//
// ctx is detached from the request's cancellation via
// [context.WithoutCancel] so the handler is not killed when the UDP
// response is flushed; caller-installed values (slog correlation
// IDs, trace spans) propagate intact.
//
// src is a [NotifySource] value snapshot — the live transport
// ResponseWriter is intentionally not exposed because by the time
// the handler runs the ACK is already out and on TCP the connection
// may be closed.
type NotifyHandler func(ctx context.Context, zone wire.Question, src NotifySource)

// serveNotify acknowledges a NOTIFY for a zone the server hosts. NOTIFY
// queries from peers about zones we don't hold receive REFUSED.
func (a *Authoritative) serveNotify(ctx context.Context, w acidns.ResponseWriter, q wire.Message) {
	b := wire.NewMessageBuilder().
		ID(q.ID()).
		Response(true).
		Opcode(wire.OpcodeNotify)
	for _, qq := range q.Questions() {
		b = b.Question(qq)
	}

	if len(q.Questions()) == 0 {
		_ = w.WriteMsg(mustBuild(setRCODE(b, q, wire.RCODEFormErr), q))
		return
	}
	zoneQ := q.Questions()[0]

	a.mu.RLock()
	_, owns := a.zones[nameKey(zoneQ.Name())]
	handler := a.notifyHandler
	policy := a.notifyPolicy
	sem := a.notifySem
	a.mu.RUnlock()
	if !owns {
		_ = w.WriteMsg(mustBuild(setRCODE(b, q, wire.RCODENotAuth), q))
		return
	}
	// Default-deny: a NOTIFY without an installed policy is refused
	// because the source-address check is the operator's call (typical
	// policies match against the configured primaries).
	if policy == nil || !policy(ctx, w, q) {
		_ = w.WriteMsg(mustBuild(setRCODE(b, q, wire.RCODERefused), q))
		return
	}

	_ = w.WriteMsg(mustBuild(echoEDNS(b, q).Authoritative(true), q))
	if handler == nil {
		return
	}

	// Bound NOTIFY handler concurrency. A storm of spoofed NOTIFY
	// (or a misbehaving primary) could otherwise spawn an unbounded
	// pool of goroutines, each typically blocked on AXFR I/O. Drop
	// silently on saturation — the primary will retry, and the ACK
	// already went out so we are not pretending to handle one we
	// can't.
	if sem != nil {
		select {
		case sem <- struct{}{}:
		default:
			return
		}
	}
	handlerCtx := context.WithoutCancel(ctx)
	src := NotifySource{
		remote:  w.RemoteAddr(),
		local:   w.LocalAddr(),
		network: w.Network(),
	}
	go func() {
		if sem != nil {
			defer func() { <-sem }()
		}
		handler(handlerCtx, zoneQ, src)
	}()
}
