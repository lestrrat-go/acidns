//go:build !acidns_no_doq

package doq

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/lestrrat-go/acidns/internal/spki"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/option/v3"
)

// KeepAliveOption configures a DoQ persistent-connection client.
type KeepAliveOption interface {
	option.Interface
	doqKeepAliveOption()
}

type doqKeepAliveOption struct{ option.Interface }

func (doqKeepAliveOption) doqKeepAliveOption() {}

// DefaultKeepAliveMaxIdleTimeout is the QUIC-layer idle timeout used
// when [WithKeepAliveMaxIdleTimeout] is not supplied. Matches the
// single-shot client's hard-coded value.
const DefaultKeepAliveMaxIdleTimeout = 30 * time.Second

type kaConfig struct {
	timeout          time.Duration
	maxIdleTimeout   time.Duration
	tlsConfig        *tls.Config
	serverName       string
	padding          bool
	insecure         bool
	maxResponseBytes int
	spkiPins         [][]byte
}

type identKATimeout struct{}
type identKAIdle struct{}
type identKATLSConfig struct{}
type identKAServerName struct{}
type identKAPadding struct{}
type identKAInsecure struct{}
type identKAMaxResponseBytes struct{}
type identKASPKIPin struct{}

// WithKeepAliveTimeout sets the per-exchange timeout used when the
// caller's context has no deadline. Defaults to 10 seconds.
func WithKeepAliveTimeout(d time.Duration) KeepAliveOption {
	return doqKeepAliveOption{option.New(identKATimeout{}, d)}
}

// WithKeepAliveMaxIdleTimeout sets the QUIC-layer idle window
// (quic.Config.MaxIdleTimeout). After this elapses with no traffic on
// the connection, quic-go closes it; the next Exchange dials fresh.
// Defaults to [DefaultKeepAliveMaxIdleTimeout].
func WithKeepAliveMaxIdleTimeout(d time.Duration) KeepAliveOption {
	return doqKeepAliveOption{option.New(identKAIdle{}, d)}
}

// WithKeepAliveTLSConfig overrides the default *tls.Config (cloned).
// The "doq" ALPN is added automatically if absent and MinVersion is
// clamped to TLS 1.3 (RFC 9250 §3).
func WithKeepAliveTLSConfig(tc *tls.Config) KeepAliveOption {
	return doqKeepAliveOption{option.New(identKATLSConfig{}, tc.Clone())}
}

// WithKeepAliveServerName sets the SNI / certificate verification name.
// Required when addr is an IP literal and no ServerName was set on the
// pre-supplied *tls.Config; the client refuses construction otherwise.
func WithKeepAliveServerName(name string) KeepAliveOption {
	return doqKeepAliveOption{option.New(identKAServerName{}, name)}
}

// WithKeepAlivePadding toggles RFC 8467 §4.1 query padding. Defaults
// to true.
func WithKeepAlivePadding(v bool) KeepAliveOption {
	return doqKeepAliveOption{option.New(identKAPadding{}, v)}
}

// WithKeepAliveInsecure disables TLS certificate verification on the
// persistent QUIC connection. Mirrors [WithInsecure] for the single-shot
// client. Use only against a known loopback / test endpoint.
func WithKeepAliveInsecure(v bool) KeepAliveOption {
	return doqKeepAliveOption{option.New(identKAInsecure{}, v)}
}

// WithKeepAliveMaxResponseBytes caps how many response bytes the client
// will allocate per stream. Defaults to [DefaultMaxResponseBytes].
func WithKeepAliveMaxResponseBytes(n int) KeepAliveOption {
	return doqKeepAliveOption{option.New(identKAMaxResponseBytes{}, n)}
}

// WithKeepAliveSPKIPin appends a SHA-256 SubjectPublicKeyInfo
// fingerprint (32 raw bytes) the resolver's leaf certificate MUST
// match. Mirrors [WithSPKIPin] for the persistent-connection client.
// Multiple calls accumulate: at least one of the registered pins must
// match. Pinning runs IN ADDITION TO PKIX validation.
//
// Pin length is validated at [NewKeepAliveClient]; supplying a
// non-32-byte pin returns [ErrInvalidSPKIPin].
func WithKeepAliveSPKIPin(pin []byte) KeepAliveOption {
	cp := make([]byte, len(pin))
	copy(cp, pin)
	return doqKeepAliveOption{option.New(identKASPKIPin{}, cp)}
}

// NewKeepAliveClient returns a *KeepAliveClient that maintains a single
// persistent QUIC connection to addr and multiplexes queries onto
// per-exchange streams. Unlike DoT keep-alive, the underlying transport
// (QUIC) supports concurrent streams natively; concurrent Exchange
// callers do not serialise.
//
// The connection idle timeout is governed by [quic.Config.MaxIdleTimeout]
// (see [WithKeepAliveMaxIdleTimeout]); a closed connection is
// transparently re-dialled on the next Exchange.
//
// *KeepAliveClient satisfies [github.com/lestrrat-go/acidns.Exchanger].
// The concrete pointer is returned so callers can reach Close without
// an interface assertion.
func NewKeepAliveClient(addr netip.AddrPort, opts ...KeepAliveOption) (*KeepAliveClient, error) {
	if !addr.IsValid() {
		return nil, ErrInvalidAddress
	}
	c := kaConfig{
		timeout:          10 * time.Second,
		maxIdleTimeout:   DefaultKeepAliveMaxIdleTimeout,
		padding:          true,
		maxResponseBytes: DefaultMaxResponseBytes,
	}
	for _, o := range opts {
		switch o.Ident() {
		case identKATimeout{}:
			c.timeout = option.MustGet[time.Duration](o)
		case identKAIdle{}:
			c.maxIdleTimeout = option.MustGet[time.Duration](o)
		case identKATLSConfig{}:
			c.tlsConfig = option.MustGet[*tls.Config](o)
		case identKAServerName{}:
			c.serverName = option.MustGet[string](o)
		case identKAPadding{}:
			c.padding = option.MustGet[bool](o)
		case identKAInsecure{}:
			c.insecure = option.MustGet[bool](o)
		case identKAMaxResponseBytes{}:
			c.maxResponseBytes = option.MustGet[int](o)
		case identKASPKIPin{}:
			c.spkiPins = append(c.spkiPins, option.MustGet[[]byte](o))
		}
	}
	for _, p := range c.spkiPins {
		if len(p) != spki.HashSize {
			return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidSPKIPin, len(p))
		}
	}
	if c.maxResponseBytes <= 0 {
		c.maxResponseBytes = DefaultMaxResponseBytes
	}

	var tcfg *tls.Config
	if c.tlsConfig != nil {
		// Refuse a caller-supplied tls.Config that already disables cert
		// verification unless WithKeepAliveInsecure(true) was also
		// passed. Same posture as [NewClient].
		if c.tlsConfig.InsecureSkipVerify && !c.insecure {
			return nil, ErrInsecureTLSConfig
		}
		tcfg = c.tlsConfig.Clone()
	} else {
		tcfg = &tls.Config{MinVersion: tls.VersionTLS13}
	}
	if tcfg.MinVersion < tls.VersionTLS13 {
		tcfg.MinVersion = tls.VersionTLS13
	}
	if !containsALPN(tcfg.NextProtos, alpn) {
		tcfg.NextProtos = append(tcfg.NextProtos, alpn)
	}
	if c.serverName != "" {
		tcfg.ServerName = c.serverName
	}
	if tcfg.ServerName == "" && !c.insecure {
		return nil, fmt.Errorf("%w (or *tls.Config.ServerName)", ErrServerNameRequired)
	}
	if c.insecure {
		tcfg.InsecureSkipVerify = true
	}
	if len(c.spkiPins) > 0 {
		prev := tcfg.VerifyConnection
		pins := c.spkiPins
		tcfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if prev != nil {
				if err := prev(cs); err != nil {
					return err
				}
			}
			return verifySPKIPin(cs, pins)
		}
	}

	return &KeepAliveClient{
		addr:      addr,
		cfg:       c,
		tlsConfig: tcfg,
		quicConfig: &quic.Config{
			MaxIdleTimeout: c.maxIdleTimeout,
			Allow0RTT:      false,
		},
	}, nil
}

// KeepAliveClient maintains a single persistent QUIC connection to a
// DoQ resolver. Per-Exchange streams ride on top of that connection;
// QUIC handles multiplexing so concurrent callers do not serialise.
//
// Construct with [NewKeepAliveClient]. The zero value is not usable.
type KeepAliveClient struct {
	addr       netip.AddrPort
	cfg        kaConfig
	tlsConfig  *tls.Config
	quicConfig *quic.Config

	mu      sync.Mutex
	conn    *quic.Conn
	dialing chan struct{} // non-nil while a dial is in flight
}

// Exchange runs one DoQ exchange over a stream on the shared QUIC
// connection. The connection is dialled lazily on the first call and
// re-dialled transparently after an idle close or a connection-level
// error.
func (e *KeepAliveClient) Exchange(ctx context.Context, q wire.Message) (wire.Message, error) {
	if e.cfg.padding {
		q = wire.PadEncrypted(q)
	}
	if _, ok := ctx.Deadline(); !ok && e.cfg.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.cfg.timeout)
		defer cancel()
	}

	// Two-attempt loop: if OpenStreamSync fails because the cached
	// connection died between acquireConn and OpenStreamSync, drop and
	// re-dial once.
	for attempt := 0; attempt < 2; attempt++ {
		conn, err := e.acquireConn(ctx)
		if err != nil {
			return wire.Message{}, err
		}
		stream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			e.dropConn(conn)
			if attempt == 0 && ctx.Err() == nil {
				continue
			}
			return wire.Message{}, fmt.Errorf("doq-keepalive: open stream: %w", err)
		}
		return e.runStream(stream, q)
	}
	return wire.Message{}, fmt.Errorf("doq-keepalive: exhausted retries")
}

// runStream writes the query and reads one response on stream. The
// stream is local to this exchange; errors here do NOT invalidate the
// shared connection.
func (e *KeepAliveClient) runStream(stream *quic.Stream, q wire.Message) (wire.Message, error) {
	defer stream.CancelRead(doqStreamRequestCancelled)
	msg, err := wire.Pack(q)
	if err != nil {
		return wire.Message{}, fmt.Errorf("doq-keepalive: marshal: %w", err)
	}
	// RFC 9250 §4.2.1: wire ID MUST be 0.
	msg[0] = 0
	msg[1] = 0
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(msg)))
	if _, err := stream.Write(hdr[:]); err != nil {
		return wire.Message{}, fmt.Errorf("doq-keepalive: write length: %w", err)
	}
	if _, err := stream.Write(msg); err != nil {
		return wire.Message{}, fmt.Errorf("doq-keepalive: write body: %w", err)
	}
	if err := stream.Close(); err != nil {
		return wire.Message{}, fmt.Errorf("doq-keepalive: close write side: %w", err)
	}
	if _, err := io.ReadFull(stream, hdr[:]); err != nil {
		return wire.Message{}, fmt.Errorf("doq-keepalive: read length: %w", err)
	}
	respLen := int(binary.BigEndian.Uint16(hdr[:]))
	if respLen > e.cfg.maxResponseBytes {
		return wire.Message{}, fmt.Errorf("%w: %d > %d", ErrResponseTooLarge, respLen, e.cfg.maxResponseBytes)
	}
	body := make([]byte, respLen)
	if _, err := io.ReadFull(stream, body); err != nil {
		return wire.Message{}, fmt.Errorf("doq-keepalive: read body: %w", err)
	}
	return decodeDoQResponse(body, q)
}

// acquireConn returns a usable QUIC connection. A live cached conn is
// reused; otherwise the caller dials outside the lock so a stalled
// handshake does not pin concurrent callers. Concurrent callers dedupe
// via the dialing channel — exactly one dial happens per epoch.
func (e *KeepAliveClient) acquireConn(ctx context.Context) (*quic.Conn, error) {
	for {
		e.mu.Lock()
		if c := e.conn; c != nil {
			// quic-go closes Context() on conn shutdown (idle, server-
			// initiated, or our own Close). A done context means the
			// cached conn is unusable; drop and re-dial.
			if c.Context().Err() == nil {
				e.mu.Unlock()
				return c, nil
			}
			e.conn = nil
		}
		if e.dialing != nil {
			ch := e.dialing
			e.mu.Unlock()
			select {
			case <-ch:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		done := make(chan struct{})
		e.dialing = done
		e.mu.Unlock()

		c, dialErr := quic.DialAddr(ctx, e.addr.String(), e.tlsConfig, e.quicConfig)

		e.mu.Lock()
		e.dialing = nil
		if dialErr == nil {
			e.conn = c
		}
		e.mu.Unlock()
		close(done)

		if dialErr != nil {
			return nil, fmt.Errorf("doq-keepalive: dial %s: %w", e.addr, dialErr)
		}
		// Loop once more so the reuse path returns the conn.
	}
}

// dropConn invalidates conn so the next Exchange dials fresh. Other
// concurrent callers may already have moved past the conn pointer — we
// close it regardless to release the QUIC resources.
func (e *KeepAliveClient) dropConn(conn *quic.Conn) {
	e.mu.Lock()
	if e.conn == conn {
		e.conn = nil
	}
	e.mu.Unlock()
	_ = conn.CloseWithError(doqNoError, "")
}

// Close releases any cached QUIC connection. Subsequent Exchange calls
// will re-handshake.
func (e *KeepAliveClient) Close() error {
	e.mu.Lock()
	conn := e.conn
	e.conn = nil
	e.mu.Unlock()
	if conn != nil {
		return conn.CloseWithError(doqNoError, "")
	}
	return nil
}
