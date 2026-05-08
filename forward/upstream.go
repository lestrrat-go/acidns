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
	udp, err := acidns.NewUDPExchanger(addr)
	if err != nil {
		return errExchanger{err: fmt.Errorf("forward: udp upstream: %w", err)}
	}
	tcp, err := acidns.NewTCPExchanger(addr)
	if err != nil {
		return errExchanger{err: fmt.Errorf("forward: tcp upstream: %w", err)}
	}
	return &udpTCPFallback{addr: addr, udp: udp, tcp: tcp}
}

func (e *udpTCPFallback) Exchange(ctx context.Context, q wire.Message) (wire.Message, error) {
	resp, err := e.udp.Exchange(ctx, q)
	if err != nil {
		return nil, err
	}
	if resp.Flags().Truncated() {
		return e.tcp.Exchange(ctx, q)
	}
	return resp, nil
}

// errExchanger surfaces a construction-time error on every Exchange so
// the configuration mistake is reported at first use rather than at
// New time, matching the pattern used elsewhere in the toolkit.
type errExchanger struct{ err error }

func (e errExchanger) Exchange(_ context.Context, _ wire.Message) (wire.Message, error) {
	return nil, e.err
}
