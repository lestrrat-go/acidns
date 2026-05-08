package authoritative

import (
	"context"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
)

// NotifyHandler is invoked once per RFC 1996 NOTIFY received for a zone
// that this server holds. The default behaviour is to ACK the NOTIFY
// without further action; a non-nil handler is run after the ACK is
// queued (the response is sent regardless of whether the handler errs).
//
// The handler is invoked on a fresh goroutine — the typical handler
// schedules an IXFR/AXFR fetch from a primary, which can block on
// network I/O. Running it on the request goroutine would pin the
// transport's per-handler concurrency slot for the duration of the
// fetch and let a single NOTIFY stall unrelated queries on the same
// listener.
type NotifyHandler func(zone wire.Question, src acidns.ResponseWriter)

// serveNotify acknowledges a NOTIFY for a zone the server hosts. NOTIFY
// queries from peers about zones we don't hold receive REFUSED.
func (a *authoritative) serveNotify(ctx context.Context, w acidns.ResponseWriter, q wire.Message) {
	b := wire.NewBuilder().
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
	if handler != nil {
		go handler(zoneQ, w)
	}
}
