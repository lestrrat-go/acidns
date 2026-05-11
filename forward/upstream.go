package forward

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
)

// udpTCPFallback exchanges over UDP and re-issues over TCP when the
// response carries the TC bit (RFC 1035 §4.2.1, RFC 7766 §5).
type udpTCPFallback struct {
	addr netip.AddrPort
	udp  acidns.Exchanger
	tcp  acidns.Exchanger
}

func newUDPTCPFallback(addr netip.AddrPort) acidns.Exchanger {
	// 0x20 case randomization (RFC 5452 §6) is on by default to mirror
	// the recursive resolver: a forwarder relying on 16-bit ID alone
	// is the classic Kaminsky-class hole.
	udp, err := acidns.NewUDPClient(addr, acidns.WithUDP0x20(true))
	if err != nil {
		return errExchanger{err: fmt.Errorf("forward: udp upstream: %w", err)}
	}
	tcp, err := acidns.NewTCPClient(addr)
	if err != nil {
		return errExchanger{err: fmt.Errorf("forward: tcp upstream: %w", err)}
	}
	return &udpTCPFallback{addr: addr, udp: udp, tcp: tcp}
}

func (e *udpTCPFallback) Exchange(ctx context.Context, q wire.Message) (wire.Message, error) {
	resp, err := e.udp.Exchange(ctx, q)
	if err != nil {
		return wire.Message{}, err
	}
	if !resp.Flags().Truncated() {
		return resp, nil
	}
	// Re-randomise the transaction ID before the TCP retry. An off-path
	// observer who saw the UDP query (or an attacker who can drop only
	// UDP) would otherwise have the ID free, which weakens the TCP
	// exchange's spoofing surface (RFC 5452 §10).
	id, err := newID()
	if err != nil {
		return wire.Message{}, err
	}
	return e.tcp.Exchange(ctx, wire.WithID(q, id))
}

// errExchanger surfaces a construction-time error on every Exchange so
// the configuration mistake is reported at first use rather than at
// New time, matching the pattern used elsewhere in the toolkit.
type errExchanger struct{ err error }

func (e errExchanger) Exchange(_ context.Context, _ wire.Message) (wire.Message, error) {
	return wire.Message{}, e.err
}
