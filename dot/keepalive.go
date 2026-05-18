package dot

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/lestrrat-go/acidns/internal/keepalive"
	"github.com/lestrrat-go/acidns/internal/spki"
	"github.com/lestrrat-go/acidns/internal/streamframe"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/option/v3"
)

// KeepAliveOption configures a DoT keep-alive Exchanger.
type KeepAliveOption interface {
	option.Interface
	dotKeepAliveOption()
}

type dotKeepAliveOption struct{ option.Interface }

func (dotKeepAliveOption) dotKeepAliveOption() {}

type kaConfig struct {
	timeout      time.Duration
	idleFallback time.Duration
	advertise    bool
	tlsConfig    *tls.Config
	serverName   string
	padding      bool
	insecure     bool
	spkiPins     [][]byte
}

type identKATimeout struct{}
type identKAIdle struct{}
type identKAAdvertise struct{}
type identKATLSConfig struct{}
type identKAServerName struct{}
type identKAPadding struct{}
type identKAInsecure struct{}
type identKASPKIPin struct{}

// WithKeepAliveTimeout sets the per-exchange I/O timeout used when the
// caller's context has no deadline. Defaults to 10 seconds — TLS
// handshake plus query/response.
func WithKeepAliveTimeout(d time.Duration) KeepAliveOption {
	return dotKeepAliveOption{option.New(identKATimeout{}, d)}
}

// WithKeepAliveIdle sets the local fallback idle window used when the
// server does not advertise an edns-tcp-keepalive timeout. After this
// elapses since the last completed exchange the cached TLS connection
// is closed and the next Exchange dials fresh. Defaults to 30 seconds.
func WithKeepAliveIdle(d time.Duration) KeepAliveOption {
	return dotKeepAliveOption{option.New(identKAIdle{}, d)}
}

// WithKeepAliveAdvertise controls whether outgoing queries are augmented
// with an empty edns-tcp-keepalive option (RFC 7828 §3.1). Defaults to
// true. RFC 7858 §3.4 explicitly endorses RFC 7828 over DoT.
func WithKeepAliveAdvertise(v bool) KeepAliveOption {
	return dotKeepAliveOption{option.New(identKAAdvertise{}, v)}
}

// WithKeepAliveTLSConfig overrides the default *tls.Config (cloned).
func WithKeepAliveTLSConfig(tc *tls.Config) KeepAliveOption {
	return dotKeepAliveOption{option.New(identKATLSConfig{}, tc.Clone())}
}

// WithKeepAliveServerName sets the SNI / certificate verification name.
// Required when addr is an IP literal and no ServerName was set on the
// pre-supplied *tls.Config — the Client refuses construction
// otherwise (see [NewClient] for the same rule).
func WithKeepAliveServerName(name string) KeepAliveOption {
	return dotKeepAliveOption{option.New(identKAServerName{}, name)}
}

// WithKeepAlivePadding toggles RFC 8467 §4.1 query padding. Defaults to
// true.
func WithKeepAlivePadding(v bool) KeepAliveOption {
	return dotKeepAliveOption{option.New(identKAPadding{}, v)}
}

// WithKeepAliveInsecure disables TLS certificate verification on the
// persistent connection. Mirrors [WithInsecure] for the single-shot
// Client: by default the keep-alive client requires a valid chain
// to a system root or to the RootCAs configured via
// [WithKeepAliveTLSConfig]; pass true here to skip that check entirely.
// Use only against a known loopback / test endpoint — disabling
// verification on a public network strips DoT of every privacy and
// authentication property the transport is meant to provide.
func WithKeepAliveInsecure(v bool) KeepAliveOption {
	return dotKeepAliveOption{option.New(identKAInsecure{}, v)}
}

// WithKeepAliveSPKIPin appends a SHA-256 SubjectPublicKeyInfo
// fingerprint (32 raw bytes) the resolver's leaf certificate MUST
// match. Mirrors [WithSPKIPin] for the persistent-connection
// client. Multiple WithKeepAliveSPKIPin calls accumulate: at least
// one of the registered pins must match. Pinning runs IN ADDITION TO
// the usual PKIX chain validation; a successful handshake requires
// both a valid chain (or [WithKeepAliveInsecure](true)) AND a matching
// pin. If the [crypto/tls.Config] carries its own VerifyConnection,
// ours runs after the caller's so the caller's check is preserved.
//
// Pin length is validated at [NewKeepAliveClient]; supplying a
// non-32-byte pin returns [ErrInvalidSPKIPin].
func WithKeepAliveSPKIPin(pin []byte) KeepAliveOption {
	cp := make([]byte, len(pin))
	copy(cp, pin)
	return dotKeepAliveOption{option.New(identKASPKIPin{}, cp)}
}

// NewKeepAliveClient returns a *KeepAliveClient that maintains a single
// persistent TLS-over-TCP connection per addr, advertising
// edns-tcp-keepalive on outgoing queries (RFC 7828) and honouring the
// timeout returned by the server. The connection is closed and
// re-dialled transparently when the server-advertised idle window
// elapses or any I/O error breaks framing.
//
// *KeepAliveClient satisfies [acidns.Exchanger]; the concrete pointer is
// returned so callers can reach Close without an interface assertion. It
// is safe for concurrent callers but serialises exchanges over the
// single connection (no pipelining).
func NewKeepAliveClient(addr netip.AddrPort, opts ...KeepAliveOption) (*KeepAliveClient, error) {
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
		switch o.Ident() {
		case identKATimeout{}:
			c.timeout = option.MustGet[time.Duration](o)
		case identKAIdle{}:
			c.idleFallback = option.MustGet[time.Duration](o)
		case identKAAdvertise{}:
			c.advertise = option.MustGet[bool](o)
		case identKATLSConfig{}:
			c.tlsConfig = option.MustGet[*tls.Config](o)
		case identKAServerName{}:
			c.serverName = option.MustGet[string](o)
		case identKAPadding{}:
			c.padding = option.MustGet[bool](o)
		case identKAInsecure{}:
			c.insecure = option.MustGet[bool](o)
		case identKASPKIPin{}:
			c.spkiPins = append(c.spkiPins, option.MustGet[[]byte](o))
		}
	}
	for _, p := range c.spkiPins {
		if len(p) != spki.HashSize {
			return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidSPKIPin, len(p))
		}
	}

	// Match the floor / ALPN / pin posture from [NewClient]; the
	// keep-alive client must not be a back-door for TLS 1.2.
	tcfg, err := spki.PrepareClient(spki.PrepareConfig{
		Base:              c.tlsConfig,
		ServerName:        c.serverName,
		ALPN:              "dot",
		Insecure:          c.insecure,
		SPKIPins:          c.spkiPins,
		ErrInsecureConfig: ErrInsecureTLSConfig,
		ErrServerNameReq:  fmt.Errorf("dot-keepalive: WithKeepAliveServerName (or *tls.Config.ServerName) required when addr is an IP literal"),
		ErrNoPeerCert:     ErrNoPeerCertificate,
		ErrSPKIMismatch:   ErrSPKIPinMismatch,
	})
	if err != nil {
		return nil, err
	}

	return &KeepAliveClient{addr: addr, cfg: c, tlsConfig: tcfg}, nil
}

// KeepAliveClient is the *Client variant that maintains a single
// persistent TLS connection across exchanges, advertising
// edns-tcp-keepalive (RFC 7828) and honouring the server-supplied idle
// window. Construct with [NewKeepAliveClient]. The zero value is not
// usable.
type KeepAliveClient struct {
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

func (e *KeepAliveClient) Exchange(ctx context.Context, q wire.Message) (wire.Message, error) {
	if e.cfg.padding {
		q = wire.PadEncrypted(q)
	}
	if e.cfg.advertise {
		q = keepalive.EnsureOption(q)
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
func (e *KeepAliveClient) acquireConn(ctx context.Context) (net.Conn, error) {
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
func (e *KeepAliveClient) dropConn(conn net.Conn) {
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
func (e *KeepAliveClient) Close() error {
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
