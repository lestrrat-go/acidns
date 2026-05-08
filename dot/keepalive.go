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

	mu       sync.Mutex
	conn     net.Conn
	deadline time.Time
}

func (e *kaExchanger) Exchange(ctx context.Context, q wire.Message) (wire.Message, error) {
	if e.cfg.padding {
		q = wire.PadEncrypted(q)
	}
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
		d := tls.Dialer{Config: e.tlsConfig, NetDialer: &net.Dialer{Timeout: e.cfg.timeout}}
		c, err := d.DialContext(ctx, "tcp", e.addr.String())
		if err != nil {
			return nil, fmt.Errorf("dot-keepalive: dial %s: %w", e.addr, err)
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

// Close releases any cached TLS connection. Subsequent Exchange calls
// will re-handshake.
func (e *kaExchanger) Close() error {
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
	b = b.EDNS(eb.Build())

	m, err := b.Build()
	if err != nil {
		return q
	}
	return m
}
