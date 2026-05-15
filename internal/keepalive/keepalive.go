// Package keepalive holds wire-level helpers for the RFC 7828
// edns-tcp-keepalive option, shared between the root acidns TCP
// keep-alive exchanger and the dot keep-alive exchanger.
package keepalive

import "github.com/lestrrat-go/acidns/wire"

// EnsureOption returns q with an edns-tcp-keepalive option (RFC 7828
// §3.1) present in the EDNS OPT RR. If q already advertises the
// option, q is returned unchanged. Otherwise a new Message is built
// preserving every other section and EDNS field.
func EnsureOption(q wire.Message) wire.Message {
	if existing, ok := q.EDNS(); ok {
		for _, o := range existing.Options() {
			if o.Code() == wire.EDNSOptionTCPKeepalive {
				return q
			}
		}
	}

	b := wire.NewMessageBuilder().
		ID(q.ID()).
		Flags(q.Flags())
	for _, qq := range q.Questions() {
		b = b.Question(qq)
	}
	for _, r := range q.Answers() {
		b = b.Answer(r)
	}
	for _, r := range q.Authorities() {
		b = b.Authority(r)
	}
	for _, r := range q.Additionals() {
		b = b.Additional(r)
	}

	eb := wire.NewEDNSBuilder()
	if existing, ok := q.EDNS(); ok {
		eb = eb.UDPSize(existing.UDPSize()).
			ExtendedRCODE(existing.ExtendedRCODE()).
			Version(existing.Version()).
			DO(existing.DO())
		for _, o := range existing.Options() {
			eb = eb.Option(o)
		}
	}
	eb = eb.Option(wire.NewTCPKeepalive(0))
	ed, err := eb.Build()
	if err != nil {
		return q
	}
	b = b.EDNS(ed)

	m, err := b.Build()
	if err != nil {
		return q
	}
	return m
}
