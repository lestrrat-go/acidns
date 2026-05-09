package validator

import (
	"context"
	"fmt"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/option/v3"
)

// Source is the validator's pluggable upstream: a Lookup function that, given
// a question, returns the full DNS Message (answer, authority, additional)
// the upstream produced. The Walker filters answers and signature material
// out of the message itself.
//
// Production callers typically pass an instance backed by their recursive
// resolver's cache so DNSKEY/DS lookups don't repeat across queries; the
// stand-alone NewExchangerSource is supplied for clients that just want
// "talk to this resolver" semantics.
type Source interface {
	Lookup(ctx context.Context, qname wire.Name, qtype rrtype.Type) (wire.Message, error)
}

// Exchanger is the minimal transport contract the validator depends on. It
// is intentionally a structural duplicate of acidns.Exchanger so this
// package does not import the root acidns package (which itself depends on
// this package via the Resolver). Any acidns.Exchanger implementation
// satisfies validator.Exchanger.
type Exchanger interface {
	Exchange(ctx context.Context, q wire.Message) (wire.Message, error)
}

// NewExchangerSource returns a Source that issues each Lookup as a fresh
// DNSSEC-OK query (DO=1, CD=1) over ex. The CD bit asks the upstream not
// to filter bogus answers — we do our own validation. UDPSize defaults to
// 1232 (DNS Flag Day 2020) but can be overridden.
func NewExchangerSource(ex Exchanger, opts ...ExchangerSourceOption) Source {
	src := &exchangerSource{ex: ex, udpSize: 1232}
	for _, o := range opts {
		switch o.Ident() {
		case identExchangerSourceUDPSize{}:
			if size := option.MustGet[uint16](o); size > 0 {
				src.udpSize = size
			}
		case identExchangerSourceID{}:
			if id := option.MustGet[func() uint16](o); id != nil {
				src.idFn = id
			}
		}
	}
	return src
}

// ExchangerSourceOption tunes NewExchangerSource.
type ExchangerSourceOption interface {
	option.Interface
	exchangerSourceOption()
}

type exchangerSourceOption struct{ option.Interface }

func (exchangerSourceOption) exchangerSourceOption() {}

type identExchangerSourceUDPSize struct{}
type identExchangerSourceID struct{}

// WithExchangerSourceUDPSize overrides the EDNS UDP buffer size advertised
// in queries. The default (1232) is the IETF Flag Day 2020 recommendation.
func WithExchangerSourceUDPSize(size uint16) ExchangerSourceOption {
	return exchangerSourceOption{option.New(identExchangerSourceUDPSize{}, size)}
}

// WithExchangerSourceID sets a fixed query ID generator. The default uses
// a per-source counter starting at 1; tests sometimes prefer a fixed value.
func WithExchangerSourceID(id func() uint16) ExchangerSourceOption {
	return exchangerSourceOption{option.New(identExchangerSourceID{}, id)}
}

type exchangerSource struct {
	ex      Exchanger
	udpSize uint16
	idFn    func() uint16
	counter uint16
}

func (s *exchangerSource) nextID() uint16 {
	if s.idFn != nil {
		return s.idFn()
	}
	s.counter++
	if s.counter == 0 {
		s.counter = 1
	}
	return s.counter
}

func (s *exchangerSource) Lookup(ctx context.Context, qname wire.Name, qtype rrtype.Type) (wire.Message, error) {
	edns, err := wire.NewEDNSBuilder().UDPSize(s.udpSize).DO(true).Build()
	if err != nil {
		return wire.Message{}, fmt.Errorf("validator: build EDNS: %w", err)
	}
	q, err := wire.NewMessageBuilder().
		ID(s.nextID()).
		Opcode(wire.OpcodeQuery).
		RecursionDesired(true).
		CheckingDisabled(true).
		Question(wire.NewQuestion(qname, qtype)).
		EDNS(edns).
		Build()
	if err != nil {
		return wire.Message{}, fmt.Errorf("validator: build query: %w", err)
	}
	return s.ex.Exchange(ctx, q)
}
