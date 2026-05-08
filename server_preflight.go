package acidns

import (
	"github.com/lestrrat-go/acidns/wire"
)

// preflightVerdict tells the per-transport dispatch loop whether to
// pass the request to the registered Handler, drop it silently, or
// answer it directly with the supplied reply.
type preflightVerdict int

const (
	preflightAccept preflightVerdict = iota
	preflightDrop
	preflightReply
)

// preflightRequest applies framework-level ingress filters that the
// transport-specific loops (UDP, TCP) share. The filters here are the
// ones that apply uniformly regardless of transport and that no
// reasonable handler would ever want to override:
//
//   - QR=1 datagrams are silently dropped per RFC 5452 §6 (only
//     queries belong on the server-side socket; a response arriving
//     here is either spoofed or a misconfigured peer).
//
//   - QDCOUNT must be exactly 1 for QUERY, UPDATE, and NOTIFY
//     opcodes. RFC 1035 §4.1.2 implies the single-question form,
//     RFC 2136 §2.3 mandates it for UPDATE, and RFC 1996 §3.7
//     restricts NOTIFY to one question. A non-conformant request is
//     answered with FORMERR rather than dropped so a misbehaving
//     client still learns its error.
//
// Other ingress concerns (ACL, rate limit, recursion gating) belong
// in middleware — they are policy, not protocol.
func preflightRequest(q wire.Message) (preflightVerdict, wire.Message) {
	if q.Flags().Response() {
		return preflightDrop, nil
	}

	op := q.Flags().Opcode()
	switch op {
	case wire.OpcodeQuery, wire.OpcodeUpdate, wire.OpcodeNotify:
		if len(q.Questions()) != 1 {
			return preflightReply, formErrReply(q)
		}
	}

	return preflightAccept, nil
}

// formErrReply mints a minimal FORMERR response that echoes the ID,
// flips QR, preserves the opcode, and clears the question section.
// It deliberately omits the offending question because the caller
// reaches this path precisely when QDCOUNT is wrong — re-emitting an
// arbitrary subset would be a guess.
func formErrReply(q wire.Message) wire.Message {
	flags := q.Flags().
		WithResponse(true).
		WithRecursionAvailable(false).
		WithRCODE(wire.RCODEFormErr)
	m, err := wire.NewBuilder().ID(q.ID()).Flags(flags).Build()
	if err != nil {
		return nil
	}
	return m
}
