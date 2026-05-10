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
	"github.com/lestrrat-go/option/v3"
)

// TCPClientOption configures a TCP Exchanger.
type TCPClientOption interface {
	option.Interface
	tcpClientOption()
}

type tcpClientOption struct{ option.Interface }

func (tcpClientOption) tcpClientOption() {}

type tcpClientConfig struct {
	timeout time.Duration
}

type identTCPTimeout struct{}

// WithTCPTimeout sets a per-exchange timeout used when the caller's
// context has no deadline. Defaults to 5 seconds. Pass 0 to disable
// the fallback — see [WithUDPTimeout] for the same semantics.
func WithTCPTimeout(d time.Duration) TCPClientOption {
	return tcpClientOption{option.New(identTCPTimeout{}, d)}
}

// TCPClient talks TCP to a single fixed address using length-prefixed
// framing (RFC 1035 §4.2.2). Each Exchange dials a fresh connection;
// callers wanting connection reuse should use [TCPKeepAliveClient].
//
// The concrete type is returned so callers can reach the streaming API
// via [TCPClient.Stream] without an interface assertion.
// [*TCPClient] satisfies [Exchanger] and [StreamExchanger].
type TCPClient struct {
	addr    netip.AddrPort
	timeout time.Duration
}

// NewTCPClient returns a TCPClient talking to addr.
func NewTCPClient(addr netip.AddrPort, opts ...TCPClientOption) (*TCPClient, error) {
	if !addr.IsValid() {
		return nil, fmt.Errorf("acidns: invalid server address")
	}
	c := tcpClientConfig{timeout: 5 * time.Second}
	for _, o := range opts {
		switch o.Ident() {
		case identTCPTimeout{}:
			c.timeout = option.MustGet[time.Duration](o)
		}
	}
	return &TCPClient{addr: addr, timeout: c.timeout}, nil
}

func (e *TCPClient) Exchange(ctx context.Context, q wire.Message) (wire.Message, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", e.addr.String())
	if err != nil {
		return wire.Message{}, fmt.Errorf("acidns: dial %s: %w", e.addr, err)
	}
	return streamframe.Exchange(ctx, conn, q, e.timeout)
}

// Stream sends q over a fresh TCP connection and returns a MessageStream
// from which the caller pulls responses. The stream MUST be closed by the
// caller to release the connection.
func (e *TCPClient) Stream(ctx context.Context, q wire.Message) (MessageStream, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", e.addr.String())
	if err != nil {
		return nil, fmt.Errorf("acidns: dial %s: %w", e.addr, err)
	}
	s, err := streamframe.NewConnStream(ctx, conn, q, e.timeout)
	if err != nil {
		return nil, fmt.Errorf("acidns: %w", err)
	}
	return s, nil
}
