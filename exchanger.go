package acidns

// This file defines the contract a DNS transport must satisfy to serve as
// the substrate for higher-level resolvers. UDP and TCP exchangers live in
// this package; DoT, DoH, DoQ are in sibling packages
// [github.com/lestrrat-go/acidns/dot], [github.com/lestrrat-go/acidns/doh],
// [github.com/lestrrat-go/acidns/doq]. Connection-oriented transports
// additionally implement [StreamExchanger] for zone-transfer-style protocols.

import (
	"context"

	"github.com/lestrrat-go/acidns/wire"
)

// Exchanger performs a single DNS request/response exchange. Implementations
// MUST honor the context deadline and cancellation. They MUST NOT retry; the
// caller's resolver is responsible for retry policy.
//
// Implementations MUST be safe for concurrent use by multiple goroutines:
// the resolver dispatches A and AAAA queries in parallel and shares one
// Exchanger across the whole process.
type Exchanger interface {
	Exchange(ctx context.Context, q wire.Message) (wire.Message, error)
}

// StreamExchanger sends a single query and returns a MessageStream from
// which the caller pulls one or more response messages. This is the
// substrate for AXFR / IXFR — protocols where a single query yields a
// stream of DNS messages bracketed by SOA records.
//
// Datagram transports (UDP) MUST NOT satisfy this interface; only the
// connection-oriented framed transports (TCP, DoT, DoQ) do. Implementations
// MUST honor the context deadline and cancellation; closing the returned
// stream MUST close the underlying connection.
//
// StreamExchanger.Stream itself MUST be safe for concurrent calls; the
// returned MessageStream is owned by a single caller and is NOT required
// to be safe for concurrent use.
type StreamExchanger interface {
	Stream(ctx context.Context, q wire.Message) (MessageStream, error)
}

// MessageStream yields the responses to a streaming query. Next blocks
// until the next message arrives; it returns io.EOF when the peer cleanly
// closes the stream. Callers MUST Close the stream when done — including on
// error and after EOF — to release the underlying connection.
//
// A MessageStream is owned by a single goroutine. Implementations are NOT
// required to be safe for concurrent use.
type MessageStream interface {
	Next(ctx context.Context) (wire.Message, error)
	Close() error
}
