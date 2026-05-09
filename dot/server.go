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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/internal/serverctl"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/option/v3"
)

// ErrServerClosed is recorded on the [Controller] after a clean
// shutdown via context cancellation.
var ErrServerClosed = errors.New("dot: server closed")

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
		return nil, fmt.Errorf("dot: handler is nil")
	}
	cfg := serverConfig{
		handshakeTimeout: 10 * time.Second,
		idleTimeout:      10 * time.Second,
		writeTimeout:     5 * time.Second,
		maxConnections:   1024,
		maxMessageSize:   16 * 1024,
		maxInflightPer:   32,
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
		case identServerWriteTimeout{}:
			cfg.writeTimeout = option.MustGet[time.Duration](o)
		case identServerMaxConnections{}:
			cfg.maxConnections = option.MustGet[int](o)
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
		return nil, fmt.Errorf("dot: WithServerTLSConfig is required (DoT cannot run without TLS)")
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

	bufSize := s.cfg.maxMessageSize
	if bufSize <= 0 {
		bufSize = 65535
	}
	loop := &serverLoop{
		ln:      ln,
		addr:    bound,
		handler: s.handler,
		cfg:     s.cfg,
	}
	if s.cfg.maxConnections > 0 {
		loop.sem = make(chan struct{}, s.cfg.maxConnections)
	}
	loop.bodyPool.New = func() any {
		b := make([]byte, bufSize)
		return &b
	}

	ctrl := &Controller{Core: serverctl.New(bound)}
	go func() {
		defer ctrl.CloseDone()
		err := loop.run(ctx)
		if err != nil && !errors.Is(err, ErrServerClosed) {
			ctrl.SetErr(err)
		}
	}()
	return ctrl, nil
}

// Controller is the runtime handle returned by [Server.Run]. It
// embeds [serverctl.Core] which provides Addr / Done / Err / Wait;
// dot-specific runtime queries belong on this type.
type Controller struct {
	serverctl.Core
}

type serverLoop struct {
	ln       net.Listener
	addr     netip.AddrPort
	handler  acidns.Handler
	cfg      serverConfig
	sem      chan struct{}
	wg       sync.WaitGroup
	bodyPool sync.Pool
}

func (l *serverLoop) run(ctx context.Context) error {
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = l.ln.Close()
		case <-stop:
		}
	}()

	defer l.wg.Wait()

	const acceptBackoffStart = 5 * time.Millisecond
	const acceptBackoffCap = time.Second
	tempBackoff := time.Duration(0)

	for {
		if l.sem != nil {
			select {
			case l.sem <- struct{}{}:
			case <-ctx.Done():
				_ = l.ln.Close()
				return ErrServerClosed
			}
		}
		conn, err := l.ln.Accept()
		if err != nil {
			if l.sem != nil {
				<-l.sem
			}
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return ErrServerClosed
			}
			if isAcceptTransient(err) {
				if tempBackoff == 0 {
					tempBackoff = acceptBackoffStart
				} else {
					tempBackoff *= 2
					if tempBackoff > acceptBackoffCap {
						tempBackoff = acceptBackoffCap
					}
				}
				timer := time.NewTimer(tempBackoff)
				select {
				case <-timer.C:
				case <-ctx.Done():
					timer.Stop()
					_ = l.ln.Close()
					return ErrServerClosed
				}
				continue
			}
			return fmt.Errorf("dot: accept: %w", err)
		}
		tempBackoff = 0
		l.wg.Add(1)
		go func(c net.Conn) {
			defer func() {
				if l.sem != nil {
					<-l.sem
				}
				l.wg.Done()
			}()
			l.serveConn(ctx, c)
		}(conn)
	}
}

func isAcceptTransient(err error) bool {
	if err == nil {
		return false
	}
	for _, target := range []syscall.Errno{
		syscall.EMFILE,
		syscall.ENFILE,
		syscall.EAGAIN,
		syscall.ENOBUFS,
		syscall.ENOMEM,
	} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

func remoteAddrFromConn(c net.Conn) netip.AddrPort {
	if ta, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return ta.AddrPort()
	}
	ap, _ := netip.ParseAddrPort(c.RemoteAddr().String())
	return ap
}

func (l *serverLoop) serveConn(ctx context.Context, raw net.Conn) {
	defer func() { _ = raw.Close() }()

	// TLS handshake bounded by handshakeTimeout (separate from
	// idleTimeout so an operator can favour long-lived idle
	// connections without simultaneously widening the
	// peer-stalls-on-ClientHello window). A non-positive value
	// disables the deadline.
	if l.cfg.handshakeTimeout > 0 {
		_ = raw.SetDeadline(time.Now().Add(l.cfg.handshakeTimeout))
	}
	tlsConn := tls.Server(raw, l.cfg.tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return
	}
	_ = raw.SetDeadline(time.Time{})

	conn := net.Conn(tlsConn)

	connCtx, connCancel := context.WithCancel(ctx)
	defer connCancel()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-stop:
		}
	}()

	var lifetimeDeadline time.Time
	if l.cfg.maxConnLifetime > 0 {
		lifetimeDeadline = time.Now().Add(l.cfg.maxConnLifetime)
	}
	remote := remoteAddrFromConn(raw)

	var writeMu sync.Mutex
	var perConnSem chan struct{}
	if l.cfg.maxInflightPer > 0 {
		perConnSem = make(chan struct{}, l.cfg.maxInflightPer)
	}
	var connWg sync.WaitGroup
	defer connWg.Wait()

	queries := 0
	for {
		if !lifetimeDeadline.IsZero() && time.Now().After(lifetimeDeadline) {
			return
		}
		if l.cfg.maxQueriesPerConn > 0 && queries >= l.cfg.maxQueriesPerConn {
			return
		}

		readDeadline := time.Time{}
		if l.cfg.idleTimeout > 0 {
			readDeadline = time.Now().Add(l.cfg.idleTimeout)
		}
		if !lifetimeDeadline.IsZero() && (readDeadline.IsZero() || lifetimeDeadline.Before(readDeadline)) {
			readDeadline = lifetimeDeadline
		}
		if !readDeadline.IsZero() {
			_ = conn.SetReadDeadline(readDeadline)
		}

		var hdr [2]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(hdr[:]))
		if l.cfg.maxMessageSize > 0 && n > l.cfg.maxMessageSize {
			return
		}

		bufp, _ := l.bodyPool.Get().(*[]byte)
		body := (*bufp)[:n]
		if _, err := io.ReadFull(conn, body); err != nil {
			l.bodyPool.Put(bufp)
			return
		}
		queries++

		if perConnSem != nil {
			select {
			case perConnSem <- struct{}{}:
			case <-connCtx.Done():
				l.bodyPool.Put(bufp)
				return
			}
		}
		connWg.Add(1)
		go func(bufp *[]byte, n int) {
			defer func() {
				l.bodyPool.Put(bufp)
				if perConnSem != nil {
					<-perConnSem
				}
				connWg.Done()
			}()
			body := (*bufp)[:n]
			q, err := wire.Unmarshal(body)
			if err != nil {
				return
			}
			w := &responseWriter{
				conn:         conn,
				remote:       remote,
				local:        l.addr,
				writeTimeout: l.cfg.writeTimeout,
				writeMu:      &writeMu,
			}
			switch verdict, reply := acidns.PreflightRequest(q); verdict {
			case acidns.PreflightDrop:
				return
			case acidns.PreflightReply:
					_ = w.WriteMsg(reply)
				return
			}
			l.handler.ServeDNS(connCtx, w, q)
		}(bufp, n)
	}
}

type responseWriter struct {
	conn         net.Conn
	remote       netip.AddrPort
	local        netip.AddrPort
	writeTimeout time.Duration
	writeMu      *sync.Mutex
}

func (w *responseWriter) RemoteAddr() netip.AddrPort { return w.remote }
func (w *responseWriter) LocalAddr() netip.AddrPort  { return w.local }
func (w *responseWriter) Network() string            { return "dot" }

func (w *responseWriter) WriteMsg(m wire.Message) error {
	buf, err := wire.Marshal(m)
	if err != nil {
		return err
	}
	if len(buf) > 0xffff {
		return fmt.Errorf("dot: response exceeds 65535 bytes")
	}
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	if w.writeTimeout > 0 {
		_ = w.conn.SetWriteDeadline(time.Now().Add(w.writeTimeout))
		defer func() { _ = w.conn.SetWriteDeadline(time.Time{}) }()
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(buf)))
	if _, err := w.conn.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.conn.Write(buf)
	return err
}
