// Package chaos answers CHAOS-class TXT identity queries per RFC 4892:
//
//	id.server.        — server identifier
//	hostname.bind.    — BIND-style hostname (legacy synonym)
//	version.server.   — server version
//	version.bind.     — BIND-style version (legacy synonym)
//
// It is intended to be composed with another authoritative or recursive
// Handler: the chaos.Handler responds to matching queries, otherwise it
// delegates to the wrapped inner Handler. Passing a nil inner makes the
// handler stand alone — non-matching queries receive REFUSED.
package chaos

import (
	"context"
	"strings"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/option/v3"
)

// New returns a Handler that answers CHAOS identity queries, delegating
// non-matching queries to inner. If inner is nil, non-matching queries
// receive a REFUSED response so this handler can stand alone. The error
// return is currently always nil; it is part of the signature so future
// option-validation can be added without breaking callers.
func New(inner acidns.Handler, opts ...Option) (acidns.Handler, error) {
	c := config{next: inner}
	for _, o := range opts {
		switch o.Ident() {
		case identIdentifier{}:
			c.id = option.MustGet[string](o)
		case identVersion{}:
			c.version = option.MustGet[string](o)
		}
	}
	return &handler{cfg: c}, nil
}

type handler struct{ cfg config }

func (h *handler) ServeDNS(ctx context.Context, w acidns.ResponseWriter, q wire.Message) {
	if len(q.Questions()) != 1 {
		h.delegateOrRefuse(ctx, w, q)
		return
	}
	qst := q.Questions()[0]
	if qst.Class() != rrtype.ClassCH || qst.Type() != rrtype.TXT {
		h.delegateOrRefuse(ctx, w, q)
		return
	}
	answer, ok := h.lookup(qst.Name())
	if !ok {
		h.delegateOrRefuse(ctx, w, q)
		return
	}
	rd, err := rdata.NewTXT(answer)
	if err != nil {
		_ = writeRefused(w, q)
		return
	}
	rec := wire.NewRecordClass(qst.Name(), rrtype.ClassCH, 0*time.Second, rd)
	resp, err := wire.NewMessageBuilder().
		ID(q.ID()).
		Response(true).
		Authoritative(true).
		Question(qst).
		Answer(rec).
		Build()
	if err != nil {
		_ = writeRefused(w, q)
		return
	}
	_ = w.WriteMsg(resp)
}

func (h *handler) lookup(n wire.Name) (string, bool) {
	s := strings.ToLower(strings.TrimSuffix(n.String(), "."))
	switch s {
	case "id.server", "hostname.bind":
		if h.cfg.id == "" {
			return "", false
		}
		return h.cfg.id, true
	case "version.server", "version.bind":
		if h.cfg.version == "" {
			return "", false
		}
		return h.cfg.version, true
	}
	return "", false
}

func (h *handler) delegateOrRefuse(ctx context.Context, w acidns.ResponseWriter, q wire.Message) {
	if h.cfg.next != nil {
		h.cfg.next.ServeDNS(ctx, w, q)
		return
	}
	_ = writeRefused(w, q)
}

func writeRefused(w acidns.ResponseWriter, q wire.Message) error {
	b := wire.NewMessageBuilder().ID(q.ID()).Response(true).RCODE(wire.RCODERefused)
	for _, qq := range q.Questions() {
		b = b.Question(qq)
	}
	resp, err := b.Build()
	if err != nil {
		return err
	}
	return w.WriteMsg(resp)
}
