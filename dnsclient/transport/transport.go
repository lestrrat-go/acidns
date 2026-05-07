// Package transport defines the contract a DNS transport must satisfy to
// serve as the substrate for higher-level resolvers. Concrete transports
// (UDP, TCP, DoT, DoH, DoQ) live in sub-packages and implement Exchanger;
// the connection-oriented ones (TCP, DoT, DoQ) additionally implement
// StreamExchanger so zone-transfer-style protocols can read the response
// stream that follows a single query.
package transport

import (
	"context"

	"github.com/lestrrat-go/acidns/wire"
)

// Exchanger performs a single DNS request/response exchange. Implementations
// MUST honor the context deadline and cancellation. They MUST NOT retry; the
// caller's resolver is responsible for retry policy.
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
type StreamExchanger interface {
	Stream(ctx context.Context, q wire.Message) (MessageStream, error)
}

// MessageStream yields the responses to a streaming query. Next blocks
// until the next message arrives; it returns io.EOF when the peer cleanly
// closes the stream. Callers MUST Close the stream when done — including on
// error and after EOF — to release the underlying connection.
type MessageStream interface {
	Next(ctx context.Context) (wire.Message, error)
	Close() error
}
