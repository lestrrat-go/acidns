package dot

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/internal/streamframe"
	"github.com/lestrrat-go/acidns/wire"
)

// KeepAliveOption configures a DoT keep-alive Exchanger.
type KeepAliveOption interface {
	applyDoTKeepAlive(*kaConfig)
}

type kaOptionFunc func(*kaConfig)

func (f kaOptionFunc) applyDoTKeepAlive(c *kaConfig) { f(c) }

type kaConfig struct {
	timeout      time.Duration
	idleFallback time.Duration
	advertise    bool
	tlsConfig    *tls.Config
	serverName   string
	padding      bool
}

// WithKeepAliveTimeout sets the per-exchange I/O timeout used when the
// caller's context has no deadline. Defaults to 10 seconds — TLS
// handshake plus query/response.
func WithKeepAliveTimeout(d time.Duration) KeepAliveOption {
	return kaOptionFunc(func(c *kaConfig) { c.timeout = d })
}

// WithKeepAliveIdle sets the local fallback idle window used when the
// server does not advertise an edns-tcp-keepalive timeout. After this
// elapses since the last completed exchange the cached TLS connection
// is closed and the next Exchange dials fresh. Defaults to 30 seconds.
func WithKeepAliveIdle(d time.Duration) KeepAliveOption {
	return kaOptionFunc(func(c *kaConfig) { c.idleFallback = d })
}

// WithKeepAliveAdvertise controls whether outgoing queries are augmented
// with an empty edns-tcp-keepalive option (RFC 7828 §3.1). Defaults to
// true. RFC 7858 §3.4 explicitly endorses RFC 7828 over DoT.
func WithKeepAliveAdvertise(v bool) KeepAliveOption {
	return kaOptionFunc(func(c *kaConfig) { c.advertise = v })
}

// WithKeepAliveTLSConfig overrides the default *tls.Config (cloned).
func WithKeepAliveTLSConfig(tc *tls.Config) KeepAliveOption {
	return kaOptionFunc(func(c *kaConfig) { c.tlsConfig = tc.Clone() })
}

// WithKeepAliveServerName sets the SNI / certificate verification name.
// Required when addr is an IP literal and no ServerName was set on the
// pre-supplied *tls.Config — the exchanger refuses construction
// otherwise (see [New] for the same rule).
func WithKeepAliveServerName(name string) KeepAliveOption {
	return kaOptionFunc(func(c *kaConfig) { c.serverName = name })
}

// WithKeepAlivePadding toggles RFC 8467 §4.1 query padding. Defaults to
// true.
func WithKeepAlivePadding(v bool) KeepAliveOption {
	return kaOptionFunc(func(c *kaConfig) { c.padding = v })
}

// NewKeepAliveExchanger returns an Exchanger that maintains a single
// persistent TLS-over-TCP connection per addr, advertising
// edns-tcp-keepalive on outgoing queries (RFC 7828) and honouring the
// timeout returned by the server. The connection is closed and
// re-dialled transparently when the server-advertised idle window
// elapses or any I/O error breaks framing.
//
// Returned exchanger is safe for concurrent callers but serialises
// exchanges over the single connection (no pipelining).
func NewKeepAliveExchanger(addr netip.AddrPort, opts ...KeepAliveOption) (acidns.Exchanger, error) {
	if !addr.IsValid() {
		return nil, fmt.Errorf("dot-keepalive: invalid server address")
	}
	c := kaConfig{
		timeout:      10 * time.Second,
		idleFallback: 30 * time.Second,
		advertise:    true,
		padding:      true,
	}
	for _, o := range opts {
		o.applyDoTKeepAlive(&c)
	}

	var tcfg *tls.Config
	if c.tlsConfig != nil {
		tcfg = c.tlsConfig.Clone()
	} else {
		tcfg = &tls.Config{MinVersion: tls.VersionTLS13}
	}
	if tcfg.MinVersion < tls.VersionTLS12 {
		tcfg.MinVersion = tls.VersionTLS12
	}
	if c.serverName != "" {
		tcfg.ServerName = c.serverName
	}
	if tcfg.ServerName == "" {
		return nil, fmt.Errorf("dot-keepalive: WithKeepAliveServerName (or *tls.Config.ServerName) required when addr is an IP literal")
	}
	// RFC 7858 §3.2 ALPN identifier.
	if !containsALPN(tcfg.NextProtos, "dot") {
		tcfg.NextProtos = append(tcfg.NextProtos, "dot")
	}

	return &kaExchanger{addr: addr, cfg: c, tlsConfig: tcfg}, nil
}

type kaExchanger struct {
	addr      netip.AddrPort
	cfg       kaConfig
	tlsConfig *tls.Config

	// dialMu guards conn / deadline / dialing. It is held only for
	// brief bookkeeping — never across the dial+TLS-handshake (which
	// can stall arbitrarily on a black-holed upstream) nor across the
	// wire exchange.
	dialMu   sync.Mutex
	conn     net.Conn
	deadline time.Time
	dialing  chan struct{} // non-nil while a dial is in flight

	// exchangeMu serialises the wire exchange (one writer + one reader
	// over a single TCP/TLS conn cannot interleave). The keepalive
	// contract is "one conn, sequential queries"; only this mutex
	// enforces that ordering.
	exchangeMu sync.Mutex
}

func (e *kaExchanger) Exchange(ctx context.Context, q wire.Message) (wire.Message, error) {
	if e.cfg.padding {
		q = wire.PadEncrypted(q)
	}
	if e.cfg.advertise {
		q = ensureKeepAliveOption(q)
	}

	conn, err := e.acquireConn(ctx)
	if err != nil {
		return nil, err
	}

	e.exchangeMu.Lock()
	defer e.exchangeMu.Unlock()

	resp, err := streamframe.ExchangeOnConn(ctx, conn, q, e.cfg.timeout)
	if err != nil {
		e.dropConn(conn)
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
	e.dialMu.Lock()
	if idle == 0 {
		// Server signals "close after this exchange" (RFC 7828 §3.3.2).
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

// acquireConn returns a usable connection. A live cached conn is
// reused; otherwise the caller dials outside dialMu so a stalled TLS
// handshake does not pin concurrent callers. Concurrent callers
// dedupe via the dialing channel — exactly one dial happens per
// epoch.
func (e *kaExchanger) acquireConn(ctx context.Context) (net.Conn, error) {
	for {
		e.dialMu.Lock()
		if e.conn != nil {
			if e.deadline.IsZero() || time.Now().Before(e.deadline) {
				c := e.conn
				e.dialMu.Unlock()
				return c, nil
			}
			// Expired — drop and re-dial.
			_ = e.conn.Close()
			e.conn = nil
			e.deadline = time.Time{}
		}
		if e.dialing != nil {
			ch := e.dialing
			e.dialMu.Unlock()
			select {
			case <-ch:
				// Someone else's dial finished; re-check state.
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		// Become the dialer.
		done := make(chan struct{})
		e.dialing = done
		e.dialMu.Unlock()

		d := tls.Dialer{Config: e.tlsConfig, NetDialer: &net.Dialer{Timeout: e.cfg.timeout}}
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
			return nil, fmt.Errorf("dot-keepalive: dial %s: %w", e.addr, dialErr)
		}
		// Loop once more so the standard reuse path returns the conn.
	}
}

// dropConn invalidates conn so the next Exchange dials fresh. If conn
// is no longer the active one (a concurrent caller already swapped it
// out) we still close it so the resource isn't leaked.
func (e *kaExchanger) dropConn(conn net.Conn) {
	e.dialMu.Lock()
	defer e.dialMu.Unlock()
	if e.conn == conn {
		e.conn = nil
		e.deadline = time.Time{}
	}
	_ = conn.Close()
}

// Close releases any cached TLS connection. Subsequent Exchange calls
// will re-handshake.
func (e *kaExchanger) Close() error {
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

// ensureKeepAliveOption mirrors the helper of the same name in the
// root acidns package. Duplicated rather than exported to keep the
// dot package self-sufficient and the API surface small.
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
	ed, err := eb.Build()
	if err != nil {
		return q
	}
	b = b.EDNS(ed)

	m, err := b.Build()
	if err != nil {
		return q
	}
	return m
}
