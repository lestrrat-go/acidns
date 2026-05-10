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
	"github.com/lestrrat-go/option/v3"
)

// TCPKeepAliveOption configures a TCP keep-alive Exchanger.
type TCPKeepAliveOption interface {
	option.Interface
	tcpKeepAliveOption()
}

type tcpKeepAliveOption struct{ option.Interface }

func (tcpKeepAliveOption) tcpKeepAliveOption() {}

type tcpKAConfig struct {
	timeout      time.Duration
	idleFallback time.Duration
	advertise    bool
}

type identTCPKeepAliveTimeout struct{}
type identTCPKeepAliveIdle struct{}
type identTCPKeepAliveAdvertise struct{}

// WithTCPKeepAliveTimeout sets the per-exchange I/O timeout used when the
// caller's context has no deadline. Defaults to 5 seconds.
func WithTCPKeepAliveTimeout(d time.Duration) TCPKeepAliveOption {
	return tcpKeepAliveOption{option.New(identTCPKeepAliveTimeout{}, d)}
}

// WithTCPKeepAliveIdle sets the local fallback idle window used when the
// server does not advertise an edns-tcp-keepalive timeout. After this
// elapses since the last completed exchange the cached connection is
// closed and the next Exchange dials fresh. Defaults to 30 seconds, the
// RFC 7766 §6.2.3 recommended client minimum.
func WithTCPKeepAliveIdle(d time.Duration) TCPKeepAliveOption {
	return tcpKeepAliveOption{option.New(identTCPKeepAliveIdle{}, d)}
}

// WithTCPKeepAliveAdvertise controls whether outgoing queries are
// augmented with an empty edns-tcp-keepalive option (RFC 7828 §3.1) when
// they have not already opted in. Defaults to true; set false if the
// caller composes the EDNS payload itself.
func WithTCPKeepAliveAdvertise(v bool) TCPKeepAliveOption {
	return tcpKeepAliveOption{option.New(identTCPKeepAliveAdvertise{}, v)}
}

// NewTCPKeepAliveExchanger returns a TCPKeepAliveExchanger that
// maintains a single persistent TCP connection per addr, advertising
// edns-tcp-keepalive on outgoing queries and honoring the timeout
// returned by the server (RFC 7766 §3, RFC 7828). The connection is
// closed and re-dialled transparently when the server-advertised idle
// window elapses or any I/O error breaks framing.
//
// The concrete type is returned so callers can call Close to release
// the cached connection without an interface assertion.
// [*TCPKeepAliveExchanger] satisfies [Exchanger]. It is safe for
// concurrent callers but serialises exchanges over the single
// connection (no pipelining).
func NewTCPKeepAliveExchanger(addr netip.AddrPort, opts ...TCPKeepAliveOption) (*TCPKeepAliveExchanger, error) {
	if !addr.IsValid() {
		return nil, fmt.Errorf("acidns: invalid server address")
	}
	c := tcpKAConfig{
		timeout:      5 * time.Second,
		idleFallback: 30 * time.Second,
		advertise:    true,
	}
	for _, o := range opts {
		switch o.Ident() {
		case identTCPKeepAliveTimeout{}:
			c.timeout = option.MustGet[time.Duration](o)
		case identTCPKeepAliveIdle{}:
			c.idleFallback = option.MustGet[time.Duration](o)
		case identTCPKeepAliveAdvertise{}:
			c.advertise = option.MustGet[bool](o)
		}
	}
	return &TCPKeepAliveExchanger{addr: addr, cfg: c}, nil
}

type TCPKeepAliveExchanger struct {
	addr netip.AddrPort
	cfg  tcpKAConfig

	// dialMu guards conn / deadline / dialing. Held only for brief
	// bookkeeping; never across the dial (which can stall arbitrarily
	// on a black-holed upstream) nor across the wire exchange.
	dialMu   sync.Mutex
	conn     net.Conn
	deadline time.Time
	dialing  chan struct{}

	// exchangeMu serialises the wire exchange (one writer + one reader
	// over a single TCP conn cannot interleave).
	exchangeMu sync.Mutex
}

func (e *TCPKeepAliveExchanger) Exchange(ctx context.Context, q wire.Message) (wire.Message, error) {
	if e.cfg.advertise {
		q = ensureKeepAliveOption(q)
	}

	conn, err := e.acquireConn(ctx)
	if err != nil {
		return wire.Message{}, err
	}

	e.exchangeMu.Lock()
	defer e.exchangeMu.Unlock()

	resp, err := streamframe.ExchangeOnConn(ctx, conn, q, e.cfg.timeout)
	if err != nil {
		e.dropConn(conn)
		return wire.Message{}, err
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
	e.dialMu.Lock()
	if idle == 0 {
		if e.conn == conn {
			_ = e.conn.Close()
			e.conn = nil
		} else {
			_ = conn.Close()
		}
		e.deadline = time.Time{}
	} else if e.conn == conn {
		e.deadline = time.Now().Add(idle)
	}
	e.dialMu.Unlock()
	return resp, nil
}

// acquireConn returns a usable connection, dialing outside dialMu so a
// stalled handshake does not pin concurrent callers. Concurrent
// callers dedupe via the dialing channel.
func (e *TCPKeepAliveExchanger) acquireConn(ctx context.Context) (net.Conn, error) {
	for {
		e.dialMu.Lock()
		if e.conn != nil {
			if e.deadline.IsZero() || time.Now().Before(e.deadline) {
				c := e.conn
				e.dialMu.Unlock()
				return c, nil
			}
			_ = e.conn.Close()
			e.conn = nil
			e.deadline = time.Time{}
		}
		if e.dialing != nil {
			ch := e.dialing
			e.dialMu.Unlock()
			select {
			case <-ch:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		done := make(chan struct{})
		e.dialing = done
		e.dialMu.Unlock()

		var d net.Dialer
		c, dialErr := d.DialContext(ctx, "tcp", e.addr.String())

		e.dialMu.Lock()
		e.dialing = nil
		if dialErr == nil {
			e.conn = c
			e.deadline = time.Time{}
		}
		e.dialMu.Unlock()
		close(done)

		if dialErr != nil {
			return nil, fmt.Errorf("acidns: dial %s: %w", e.addr, dialErr)
		}
	}
}

func (e *TCPKeepAliveExchanger) dropConn(conn net.Conn) {
	e.dialMu.Lock()
	defer e.dialMu.Unlock()
	if e.conn == conn {
		e.conn = nil
		e.deadline = time.Time{}
	}
	_ = conn.Close()
}

// Close releases any cached connection. Subsequent Exchange calls will
// dial fresh.
func (e *TCPKeepAliveExchanger) Close() error {
	e.dialMu.Lock()
	defer e.dialMu.Unlock()
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

	b := wire.NewMessageBuilder().
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
	ed, err := eb.Build()
	if err != nil {
		return q
	}
	b = b.EDNS(ed)

	m, err := b.Build()
	if err != nil {
		// Builder errors here are programmer-level — fall back to original.
		return q
	}
	return m
}
