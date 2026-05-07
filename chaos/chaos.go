// Package chaos answers CHAOS-class TXT identity queries per RFC 4892:
//
//	id.server.        — server identifier
//	hostname.bind.    — BIND-style hostname (legacy synonym)
//	version.server.   — server version
//	version.bind.     — BIND-style version (legacy synonym)
//
// It is intended to be composed with another authoritative or recursive
// Handler: the chaos.Handler responds to matching queries, otherwise it
// delegates to the wrapped next Handler.
package chaos

import (
	"context"
	"strings"
	"time"

	"github.com/lestrrat-go/acidns/dnsserver"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// Option customises the chaos handler.
type Option interface {
	apply(*config)
}

type optionFunc func(*config)

func (f optionFunc) apply(c *config) { f(c) }

type config struct {
	id      string
	version string
	next    dnsserver.Handler
}

// WithIdentifier sets the response for id.server. and hostname.bind.
// queries. Empty string disables matching for those names.
func WithIdentifier(id string) Option {
	return optionFunc(func(c *config) { c.id = id })
}

// WithVersion sets the response for version.server. and version.bind.
// queries. Empty string disables matching for those names.
func WithVersion(version string) Option {
	return optionFunc(func(c *config) { c.version = version })
}

// WithNext sets the Handler to delegate to when the query is not a CHAOS
// identity query handled by this Handler. Without WithNext, non-matching
// queries receive a REFUSED response so this handler can stand alone.
func WithNext(h dnsserver.Handler) Option {
	return optionFunc(func(c *config) { c.next = h })
}

// New returns a Handler that answers CHAOS identity queries.
func New(opts ...Option) dnsserver.Handler {
	c := config{}
	for _, o := range opts {
		o.apply(&c)
	}
	return &handler{cfg: c}
}

type handler struct{ cfg config }

func (h *handler) ServeDNS(ctx context.Context, w dnsserver.ResponseWriter, q wire.Message) {
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
	resp, err := wire.NewBuilder().
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

func (h *handler) delegateOrRefuse(ctx context.Context, w dnsserver.ResponseWriter, q wire.Message) {
	if h.cfg.next != nil {
		h.cfg.next.ServeDNS(ctx, w, q)
		return
	}
	_ = writeRefused(w, q)
}

func writeRefused(w dnsserver.ResponseWriter, q wire.Message) error {
	b := wire.NewBuilder().ID(q.ID()).Response(true).RCODE(wire.RCODERefused)
	for _, qq := range q.Questions() {
		b = b.Question(qq)
	}
	resp, err := b.Build()
	if err != nil {
		return err
	}
	return w.WriteMsg(resp)
}
