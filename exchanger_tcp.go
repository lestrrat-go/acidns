package acidns

// TCP exchanger: a DNS Exchanger over TCP using the standard 2-byte
// length-prefixed framing of RFC 1035 §4.2.2.
//
// Each Exchange opens a fresh connection. Connection pooling is intentionally
// out of scope for the toolkit's primitive transports — higher layers may
// wrap this Exchanger to add reuse, persistent connections (RFC 7766), or
// pipelining.

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/lestrrat-go/acidns/internal/streamframe"
	"github.com/lestrrat-go/acidns/wire"
)

// TCPExchangerOption configures a TCP Exchanger.
type TCPExchangerOption interface{ applyTCPExchanger(*tcpExchangerConfig) }

type tcpExchangerOptionFunc func(*tcpExchangerConfig)

func (f tcpExchangerOptionFunc) applyTCPExchanger(c *tcpExchangerConfig) { f(c) }

type tcpExchangerConfig struct {
	timeout time.Duration
}

// WithTCPTimeout sets a per-exchange timeout used when the caller's
// context has no deadline. Defaults to 5 seconds. Pass 0 to disable
// the fallback — see [WithUDPTimeout] for the same semantics.
func WithTCPTimeout(d time.Duration) TCPExchangerOption {
	return tcpExchangerOptionFunc(func(c *tcpExchangerConfig) { c.timeout = d })
}

type tcpExchanger struct {
	addr    netip.AddrPort
	timeout time.Duration
}

// NewTCPExchanger returns an Exchanger that talks TCP to addr.
func NewTCPExchanger(addr netip.AddrPort, opts ...TCPExchangerOption) (Exchanger, error) {
	if !addr.IsValid() {
		return nil, fmt.Errorf("tcp: invalid server address")
	}
	c := tcpExchangerConfig{timeout: 5 * time.Second}
	for _, o := range opts {
		o.applyTCPExchanger(&c)
	}
	return &tcpExchanger{addr: addr, timeout: c.timeout}, nil
}

func (e *tcpExchanger) Exchange(ctx context.Context, q wire.Message) (wire.Message, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", e.addr.String())
	if err != nil {
		return nil, fmt.Errorf("tcp: dial %s: %w", e.addr, err)
	}
	return streamframe.Exchange(ctx, conn, q, e.timeout)
}

// Stream sends q over a fresh TCP connection and returns a MessageStream
// from which the caller pulls responses. The stream MUST be closed by the
// caller to release the connection.
func (e *tcpExchanger) Stream(ctx context.Context, q wire.Message) (MessageStream, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", e.addr.String())
	if err != nil {
		return nil, fmt.Errorf("tcp: dial %s: %w", e.addr, err)
	}
	s, err := streamframe.NewConnStream(ctx, conn, q, e.timeout)
	if err != nil {
		return nil, fmt.Errorf("tcp: %w", err)
	}
	return s, nil
}
