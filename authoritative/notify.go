package authoritative

import (
	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
)

// NotifyHandler is invoked once per RFC 1996 NOTIFY received for a zone
// that this server holds. The default behaviour is to ACK the NOTIFY
// without further action; a non-nil handler is run after the ACK is
// queued (the response is sent regardless of whether the handler errs).
type NotifyHandler func(zone wire.Question, src acidns.ResponseWriter)

// serveNotify acknowledges a NOTIFY for a zone the server hosts. NOTIFY
// queries from peers about zones we don't hold receive REFUSED.
func (a *authoritative) serveNotify(w acidns.ResponseWriter, q wire.Message) {
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
	a.mu.RUnlock()
	if !owns {
		_ = w.WriteMsg(mustBuild(setRCODE(b, q, wire.RCODENotAuth), q))
		return
	}

	_ = w.WriteMsg(mustBuild(echoEDNS(b, q).Authoritative(true), q))
	if handler != nil {
		handler(zoneQ, w)
	}
}
