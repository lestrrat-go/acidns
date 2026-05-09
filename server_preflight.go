package acidns

import (
	"github.com/lestrrat-go/acidns/wire"
)

// PreflightVerdict tells the per-transport dispatch loop whether to
// pass the request to the registered Handler, drop it silently, or
// answer it directly with the supplied reply.
type PreflightVerdict int

const (
	// PreflightAccept means dispatch to the Handler.
	PreflightAccept PreflightVerdict = iota
	// PreflightDrop means silently discard the request without
	// reply (RFC 5452 §6 for QR=1 datagrams).
	PreflightDrop
	// PreflightReply means write the supplied reply back instead of
	// dispatching (typically a FORMERR).
	PreflightReply
)

// PreflightRequest applies framework-level ingress filters that the
// transport-specific loops share. The filters here are the ones that
// apply uniformly regardless of transport and that no reasonable
// handler would ever want to override:
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
// The function is exported so the transport packages outside the
// root acidns package (dot, doh, doq, dnscrypt, forward, …) can
// share the exact same gate. Other ingress concerns (ACL, rate
// limit, recursion gating) belong in middleware — they are policy,
// not protocol.
func PreflightRequest(q wire.Message) (PreflightVerdict, wire.Message) {
	if q.Flags().Response() {
		return PreflightDrop, wire.Message{}
	}

	op := q.Flags().Opcode()
	switch op {
	case wire.OpcodeQuery, wire.OpcodeUpdate, wire.OpcodeNotify:
		if len(q.Questions()) != 1 {
			reply, ok := formErrReply(q)
			if !ok {
				// Builder failed — downgrade to silent drop rather
				// than emit a malformed reply.
				return PreflightDrop, wire.Message{}
			}
			return PreflightReply, reply
		}
	}

	return PreflightAccept, wire.Message{}
}

// formErrReply mints a minimal FORMERR response that echoes the ID,
// flips QR, preserves the opcode, and clears the question section.
// It deliberately omits the offending question because the caller
// reaches this path precisely when QDCOUNT is wrong — re-emitting an
// arbitrary subset would be a guess.
//
// When the request carried an OPT pseudo-RR, the response echoes a
// minimal OPT (UDPSize, version, DO bit) so EDNS-aware peers do not
// mistake the FORMERR for an EDNS-incapable server and downgrade
// their future requests (RFC 6891 §6.1.1).
//
// The advertised UDPSize is clamped to formErrUDPSize (DNS Flag Day
// 2020 default) so a peer cannot have us echo an attacker-chosen large
// value (e.g. 65535) that downstream caches might otherwise trust.
func formErrReply(q wire.Message) (wire.Message, bool) {
	flags := q.Flags().
		WithResponse(true).
		WithRecursionAvailable(false).
		WithRCODE(wire.RCODEFormErr)
	b := wire.NewMessageBuilder().ID(q.ID()).Flags(flags)
	if e, ok := q.EDNS(); ok {
		size := min(e.UDPSize(), formErrUDPSize)
		ed, err := wire.NewEDNSBuilder().
			UDPSize(size).
			Version(e.Version()).
			DO(e.DO()).
			Build()
		if err != nil {
			return wire.Message{}, false
		}
		b = b.EDNS(ed)
	}
	m, err := b.Build()
	if err != nil {
		return wire.Message{}, false
	}
	return m, true
}

// formErrUDPSize is the maximum EDNS UDPSize the FORMERR reply will
// advertise. It mirrors the DNS Flag Day 2020 / RFC 9715 ceiling used
// throughout the project.
const formErrUDPSize uint16 = 1232
