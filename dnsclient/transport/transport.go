// Package transport defines the contract a DNS transport must satisfy to
// serve as the substrate for higher-level resolvers. Concrete transports
// (UDP, TCP, DoT, DoH, DoQ) live in sub-packages and implement Exchanger.
package transport

import (
	"context"

	"github.com/lestrrat-go/acidns/dnsmsg"
)

// Exchanger performs a single DNS request/response exchange. Implementations
// MUST honor the context deadline and cancellation. They MUST NOT retry; the
// caller's resolver is responsible for retry policy.
type Exchanger interface {
	Exchange(ctx context.Context, q dnsmsg.Message) (dnsmsg.Message, error)
}
