// Package udp implements a Datagram-style DNS Exchanger over UDP.
//
// It performs a single send and reads datagrams until one whose ID matches
// the request is received, the context fires, or an unrecoverable I/O error
// occurs. It does NOT retry on truncation; callers wanting TCP fall-back are
// expected to compose two transports at the resolver layer.
package acidns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/lestrrat-go/acidns/wire"
)

// UDPExchangerOption configures a UDP Exchanger.
type UDPExchangerOption interface{ applyUDPExchanger(*udpExchangerConfig) }

type udpExchangerOptionFunc func(*udpExchangerConfig)

func (f udpExchangerOptionFunc) applyUDPExchanger(c *udpExchangerConfig) { f(c) }

type udpExchangerConfig struct {
	timeout    time.Duration
	bufferSize int
}

// WithUDPTimeout sets a per-exchange timeout that takes effect when the caller
// supplies a context without its own deadline. Defaults to 5 seconds.
func WithUDPTimeout(d time.Duration) UDPExchangerOption {
	return udpExchangerOptionFunc(func(c *udpExchangerConfig) { c.timeout = d })
}

// WithUDPReadBufferSize sets the size of the UDP read buffer in bytes. Defaults
// to 4096, which fits a typical EDNS-extended response.
func WithUDPReadBufferSize(n int) UDPExchangerOption {
	return udpExchangerOptionFunc(func(c *udpExchangerConfig) { c.bufferSize = n })
}

type udpExchanger struct {
	addr    netip.AddrPort
	timeout time.Duration
	bufsize int
}

// New returns an Exchanger that talks UDP to addr.
func NewUDPExchanger(addr netip.AddrPort, opts ...UDPExchangerOption) (Exchanger, error) {
	if !addr.IsValid() {
		return nil, fmt.Errorf("udp: invalid server address")
	}
	c := udpExchangerConfig{timeout: 5 * time.Second, bufferSize: 4096}
	for _, o := range opts {
		o.applyUDPExchanger(&c)
	}
	return &udpExchanger{addr: addr, timeout: c.timeout, bufsize: c.bufferSize}, nil
}

func (e *udpExchanger) Exchange(ctx context.Context, q wire.Message) (wire.Message, error) {
	msg, err := wire.Marshal(q)
	if err != nil {
		return nil, fmt.Errorf("udp: marshal query: %w", err)
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", e.addr.String())
	if err != nil {
		return nil, fmt.Errorf("udp: dial %s: %w", e.addr, err)
	}
	defer func() { _ = conn.Close() }()

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else if e.timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(e.timeout))
	}

	// Close on ctx cancel so a blocked Read returns promptly.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-stop:
		}
	}()

	if _, err := conn.Write(msg); err != nil {
		return nil, fmt.Errorf("udp: write: %w", err)
	}

	buf := make([]byte, e.bufsize)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return nil, cerr
			}
			return nil, fmt.Errorf("udp: read: %w", err)
		}
		resp, err := wire.Unmarshal(buf[:n])
		if err != nil {
			// Malformed datagrams are dropped silently per RFC 1035 §7.3
			// (server is misbehaving) — but only if there's still time.
			if errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return nil, ctx.Err()
			}
			continue
		}
		if resp.ID() != q.ID() {
			continue
		}
		return resp, nil
	}
}
