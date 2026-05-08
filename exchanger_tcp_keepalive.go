package acidns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/lestrrat-go/acidns/internal/streamframe"
	"github.com/lestrrat-go/acidns/wire"
)

// TCPKeepAliveOption configures a TCP keep-alive Exchanger.
type TCPKeepAliveOption interface {
	applyTCPKeepAlive(*tcpKAConfig)
}

type tcpKAOptionFunc func(*tcpKAConfig)

func (f tcpKAOptionFunc) applyTCPKeepAlive(c *tcpKAConfig) { f(c) }

type tcpKAConfig struct {
	timeout      time.Duration
	idleFallback time.Duration
	advertise    bool
}

// WithTCPKeepAliveTimeout sets the per-exchange I/O timeout used when the
// caller's context has no deadline. Defaults to 5 seconds.
func WithTCPKeepAliveTimeout(d time.Duration) TCPKeepAliveOption {
	return tcpKAOptionFunc(func(c *tcpKAConfig) { c.timeout = d })
}

// WithTCPKeepAliveIdle sets the local fallback idle window used when the
// server does not advertise an edns-tcp-keepalive timeout. After this
// elapses since the last completed exchange the cached connection is
// closed and the next Exchange dials fresh. Defaults to 30 seconds, the
// RFC 7766 §6.2.3 recommended client minimum.
func WithTCPKeepAliveIdle(d time.Duration) TCPKeepAliveOption {
	return tcpKAOptionFunc(func(c *tcpKAConfig) { c.idleFallback = d })
}

// WithTCPKeepAliveAdvertise controls whether outgoing queries are
// augmented with an empty edns-tcp-keepalive option (RFC 7828 §3.1) when
// they have not already opted in. Defaults to true; set false if the
// caller composes the EDNS payload itself.
func WithTCPKeepAliveAdvertise(v bool) TCPKeepAliveOption {
	return tcpKAOptionFunc(func(c *tcpKAConfig) { c.advertise = v })
}

// NewTCPKeepAliveExchanger returns an Exchanger that maintains a single
// persistent TCP connection per addr, advertising edns-tcp-keepalive on
// outgoing queries and honoring the timeout returned by the server (RFC
// 7766 §3, RFC 7828). The connection is closed and re-dialled
// transparently when the server-advertised idle window elapses or any
// I/O error breaks framing.
//
// The returned exchanger is safe for concurrent callers but serialises
// exchanges over the single connection (no pipelining).
func NewTCPKeepAliveExchanger(addr netip.AddrPort, opts ...TCPKeepAliveOption) (Exchanger, error) {
	if !addr.IsValid() {
		return nil, fmt.Errorf("tcp-keepalive: invalid server address")
	}
	c := tcpKAConfig{
		timeout:      5 * time.Second,
		idleFallback: 30 * time.Second,
		advertise:    true,
	}
	for _, o := range opts {
		o.applyTCPKeepAlive(&c)
	}
	return &tcpKAExchanger{addr: addr, cfg: c}, nil
}

type tcpKAExchanger struct {
	addr netip.AddrPort
	cfg  tcpKAConfig

	mu       sync.Mutex
	conn     net.Conn
	deadline time.Time
}

func (e *tcpKAExchanger) Exchange(ctx context.Context, q wire.Message) (wire.Message, error) {
	if e.cfg.advertise {
		q = ensureKeepAliveOption(q)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.conn != nil && !e.deadline.IsZero() && time.Now().After(e.deadline) {
		_ = e.conn.Close()
		e.conn = nil
	}

	if e.conn == nil {
		var d net.Dialer
		c, err := d.DialContext(ctx, "tcp", e.addr.String())
		if err != nil {
			return nil, fmt.Errorf("tcp-keepalive: dial %s: %w", e.addr, err)
		}
		e.conn = c
	}

	resp, err := streamframe.ExchangeOnConn(ctx, e.conn, q, e.cfg.timeout)
	if err != nil {
		_ = e.conn.Close()
		e.conn = nil
		return nil, err
	}

	idle := e.cfg.idleFallback
	if ed, ok := resp.EDNS(); ok {
		for _, o := range ed.Options() {
			if d, ok := wire.TCPKeepaliveTimeout(o); ok {
				idle = d
				break
			}
		}
	}
	if idle == 0 {
		// Server signals "close after this exchange" (RFC 7828 §3.3.2).
		_ = e.conn.Close()
		e.conn = nil
		e.deadline = time.Time{}
	} else {
		e.deadline = time.Now().Add(idle)
	}
	return resp, nil
}

// Close releases any cached connection. Subsequent Exchange calls will
// dial fresh.
func (e *tcpKAExchanger) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.conn != nil {
		err := e.conn.Close()
		e.conn = nil
		e.deadline = time.Time{}
		return err
	}
	return nil
}

// ensureKeepAliveOption returns q with an edns-tcp-keepalive option
// (RFC 7828 §3.1) present in the EDNS OPT RR. If q already advertises
// the option, q is returned unchanged. Otherwise a new Message is built
// preserving every other section and EDNS field.
func ensureKeepAliveOption(q wire.Message) wire.Message {
	if existing, ok := q.EDNS(); ok {
		for _, o := range existing.Options() {
			if o.Code() == wire.EDNSOptionTCPKeepalive {
				return q
			}
		}
	}

	b := wire.NewBuilder().
		ID(q.ID()).
		Flags(q.Flags())
	for _, qq := range q.Questions() {
		b = b.Question(qq)
	}
	for _, r := range q.Answers() {
		b = b.Answer(r)
	}
	for _, r := range q.Authorities() {
		b = b.Authority(r)
	}
	for _, r := range q.Additionals() {
		b = b.Additional(r)
	}

	eb := wire.NewEDNSBuilder()
	if existing, ok := q.EDNS(); ok {
		eb = eb.UDPSize(existing.UDPSize()).
			ExtendedRCODE(existing.ExtendedRCODE()).
			Version(existing.Version()).
			DO(existing.DO())
		for _, o := range existing.Options() {
			eb = eb.Option(o)
		}
	}
	eb = eb.Option(wire.NewTCPKeepalive(0))
	b = b.EDNS(eb.Build())

	m, err := b.Build()
	if err != nil {
		// Builder errors here are programmer-level — fall back to original.
		return q
	}
	return m
}
