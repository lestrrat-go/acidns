package dot

// DoT server. Mirrors the shape of [acidns.TCPServer]: an immutable
// configuration carrier whose Run binds a socket and spawns the
// accept-and-dispatch goroutine. The transport-side defenses (idle
// timeout, write timeout, max in-flight per connection, max message
// size) match the TCP server's defaults; on top of those, every
// accepted connection is wrapped in tls.Server with the supplied
// *tls.Config before the framed exchange begins.
//
// # TLS posture
//
// Out of the box the server enforces TLS 1.3 minimum and advertises
// the "dot" ALPN identifier per RFC 7858 §3.2. A caller who supplies
// a *tls.Config via [WithServerTLSConfig] gets every other knob —
// certificate roots, mTLS, session-ticket policy, KeyLogWriter — at
// the cost of being responsible for those choices.
//
// # Lifecycle
//
//	srv, err := dot.NewServer(addr, h, dot.WithServerTLSConfig(tc))
//	ctrl, err := srv.Run(ctx)
//	defer cancel()
//	<-ctrl.Done()
//
// Cancelling ctx closes the listener and drains in-flight handlers
// before Done fires. Run may be called multiple times to spawn
// multiple independent instances.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/internal/serverctl"
	"github.com/lestrrat-go/acidns/internal/streamframe"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/option/v3"
)

// ErrServerClosed is recorded on the [Controller] after a clean
// shutdown via context cancellation. Aliased to
// [acidns.ErrServerClosed] so transport-agnostic callers can match
// either form via errors.Is.
var ErrServerClosed = acidns.ErrServerClosed

// Server is an immutable configuration holder for a DoT server. The
// type carries the bind address, the [acidns.Handler], and applied
// options; runtime state lives entirely on the [*Controller] returned
// by [Server.Run].
type Server struct {
	addr    netip.AddrPort
	handler acidns.Handler
	cfg     serverConfig
}

// NewServer validates the configuration. It does NOT bind a socket;
// pass the result to [Server.Run] when you're ready to start serving.
// Returns an error when the handler is nil or no TLS config is
// supplied: a DoT server without TLS is no longer DoT.
func NewServer(addr netip.AddrPort, h acidns.Handler, opts ...ServerOption) (*Server, error) {
	if h == nil {
		return nil, ErrNilHandler
	}
	cfg := serverConfig{
		handshakeTimeout:   10 * time.Second,
		idleTimeout:        10 * time.Second,
		messageReadTimeout: 5 * time.Second,
		writeTimeout:       5 * time.Second,
		maxConnections:     1024,
		maxConnsPerSource:  32,
		maxMessageSize:     16 * 1024,
		maxInflightPer:     32,
		// Match TCP defaults — DoT amortises TLS state across many
		// queries on a long-lived connection, so an unbounded
		// per-connection budget is at least as risky here as on TCP.
		maxQueriesPerConn: 10000,
		maxConnLifetime:   time.Hour,
	}
	for _, o := range opts {
		switch o.Ident() {
		case identServerTLSConfig{}:
			cfg.tlsConfig = option.MustGet[*tls.Config](o)
		case identServerHandshakeTimeout{}:
			cfg.handshakeTimeout = option.MustGet[time.Duration](o)
		case identServerIdleTimeout{}:
			cfg.idleTimeout = option.MustGet[time.Duration](o)
		case identServerMessageReadTimeout{}:
			cfg.messageReadTimeout = option.MustGet[time.Duration](o)
		case identServerWriteTimeout{}:
			cfg.writeTimeout = option.MustGet[time.Duration](o)
		case identServerMaxConnections{}:
			cfg.maxConnections = option.MustGet[int](o)
		case identServerMaxConnsPerSource{}:
			cfg.maxConnsPerSource = option.MustGet[int](o)
		case identServerMaxMessageSize{}:
			cfg.maxMessageSize = option.MustGet[int](o)
		case identServerMaxQueriesPerConn{}:
			cfg.maxQueriesPerConn = option.MustGet[int](o)
		case identServerMaxConnLifetime{}:
			cfg.maxConnLifetime = option.MustGet[time.Duration](o)
		case identServerMaxInflightPerConn{}:
			cfg.maxInflightPer = option.MustGet[int](o)
		}
	}
	if cfg.tlsConfig == nil {
		return nil, fmt.Errorf("%w (DoT cannot run without TLS)", ErrTLSConfigRequired)
	}
	tc := cfg.tlsConfig.Clone()
	if tc.MinVersion == 0 {
		tc.MinVersion = tls.VersionTLS13
	}
	// RFC 7858 §3.2 forbids TLS < 1.2; floor regardless of caller config so
	// a copy-pasted tls.Config can't silently downgrade the server.
	if tc.MinVersion < tls.VersionTLS12 {
		tc.MinVersion = tls.VersionTLS12
	}
	if !slices.Contains(tc.NextProtos, "dot") {
		tc.NextProtos = append(tc.NextProtos, "dot")
	}
	cfg.tlsConfig = tc
	return &Server{addr: addr, handler: h, cfg: cfg}, nil
}

// Run binds a fresh TCP socket and spawns the accept-and-dispatch
// goroutine. The returned [*Controller] is the sole handle to the
// running instance. Cancelling ctx stops it.
func (s *Server) Run(ctx context.Context) (*Controller, error) {
	ln, err := net.Listen("tcp", s.addr.String()) //nolint:noctx // socket lifetime is bound to Run's ctx, not the bind call
	if err != nil {
		return nil, fmt.Errorf("dot: listen %s: %w", s.addr, err)
	}
	la, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		_ = ln.Close()
		return nil, fmt.Errorf("dot: listen %s: unexpected addr type %T", s.addr, ln.Addr())
	}
	bound := netip.AddrPortFrom(la.AddrPort().Addr(), uint16(la.Port))

	tlsConfig := s.cfg.tlsConfig
	handler := s.handler
	dispatch := streamframe.DispatcherFunc(func(ctx context.Context, w *streamframe.ResponseWriter, q wire.Message, _ []byte) {
		switch verdict, reply := acidns.PreflightRequest(q); verdict {
		case acidns.PreflightDrop:
			return
		case acidns.PreflightReply:
			_ = w.WriteMsg(reply)
			return
		}
		handler.ServeDNS(ctx, w, q)
	})

	prepare := func(ctx context.Context, raw net.Conn) (net.Conn, error) {
		tlsConn := tls.Server(raw, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		return tlsConn, nil
	}

	loopCfg := streamframe.LoopConfig{
		Listener:           ln,
		LocalAddr:          bound,
		Network:            "dot",
		Dispatcher:         dispatch,
		PrepareConn:        prepare,
		HandshakeTimeout:   s.cfg.handshakeTimeout,
		MaxConnections:     s.cfg.maxConnections,
		MaxConnsPerSource:  s.cfg.maxConnsPerSource,
		IdleTimeout:        s.cfg.idleTimeout,
		MessageReadTimeout: s.cfg.messageReadTimeout,
		WriteTimeout:       s.cfg.writeTimeout,
		MaxLifetime:        s.cfg.maxConnLifetime,
		MaxQueriesPerConn:  s.cfg.maxQueriesPerConn,
		MaxMessageSize:     s.cfg.maxMessageSize,
		MaxInflightPerConn: s.cfg.maxInflightPer,
		AcceptErrorWrap:    "dot: accept",
	}

	ctrl := &Controller{Core: serverctl.New(bound)}
	go func() {
		defer ctrl.CloseDone()
		err := streamframe.Run(ctx, loopCfg)
		if err == nil || errors.Is(err, streamframe.ErrServerClosed) {
			return
		}
		ctrl.SetErr(err)
	}()
	return ctrl, nil
}

// Controller is the runtime handle returned by [Server.Run]. It
// embeds [serverctl.Core] which provides Addr / Done / Err / Wait;
// dot-specific runtime queries belong on this type.
type Controller struct {
	serverctl.Core
}
