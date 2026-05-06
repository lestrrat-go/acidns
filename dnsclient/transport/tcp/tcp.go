// Package tcp implements a DNS Exchanger over TCP using the standard 2-byte
// length-prefixed framing of RFC 1035 §4.2.2.
//
// Each Exchange opens a fresh connection. Connection pooling is intentionally
// out of scope for the toolkit's primitive transports — higher layers may
// wrap this Exchanger to add reuse, persistent connections (RFC 7766), or
// pipelining.
package tcp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient/transport"
	"github.com/lestrrat-go/acidns/dnsclient/transport/internal/streamframe"
	"github.com/lestrrat-go/acidns/dnsmsg"
)

// Option configures a TCP Exchanger.
type Option interface{ applyTCP(*config) }

type optionFunc func(*config)

func (f optionFunc) applyTCP(c *config) { f(c) }

type config struct {
	timeout time.Duration
}

// WithTimeout sets a per-exchange timeout used when the caller's context
// has no deadline. Defaults to 5 seconds.
func WithTimeout(d time.Duration) Option {
	return optionFunc(func(c *config) { c.timeout = d })
}

type exchanger struct {
	addr    netip.AddrPort
	timeout time.Duration
}

// New returns an Exchanger that talks TCP to addr.
func New(addr netip.AddrPort, opts ...Option) (transport.Exchanger, error) {
	if !addr.IsValid() {
		return nil, fmt.Errorf("tcp: invalid server address")
	}
	c := config{timeout: 5 * time.Second}
	for _, o := range opts {
		o.applyTCP(&c)
	}
	return &exchanger{addr: addr, timeout: c.timeout}, nil
}

func (e *exchanger) Exchange(ctx context.Context, q dnsmsg.Message) (dnsmsg.Message, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", e.addr.String())
	if err != nil {
		return nil, fmt.Errorf("tcp: dial %s: %w", e.addr, err)
	}
	return streamframe.Exchange(ctx, conn, q, e.timeout)
}
