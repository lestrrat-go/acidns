//go:build !acidns_no_doq

package doq

// DoQ server (RFC 9250). Each accepted QUIC connection multiplexes
// queries on its own bidirectional streams; the handler reads a
// length-prefixed query (RFC 9250 §4.2.1 — same framing as TCP /
// DoT), enforces wire ID == 0 per §4.2.1, dispatches to the
// supplied [acidns.Handler], and writes a length-prefixed response
// before FIN'ing the stream.
//
// # Lifecycle
//
//	srv, err := doq.NewServer(addr, h, doq.WithServerTLSConfig(tc))
//	ctrl, err := srv.Run(ctx)
//	defer cancel()
//	<-ctrl.Done()
//
// As with the rest of the acidns server family, cancelling ctx is
// the only way to stop the server; the goroutine drains in-flight
// stream goroutines before Done fires. Run may be called multiple
// times to spawn parallel instances.

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
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
)

// ErrServerClosed is recorded on the [Controller] after a clean
// shutdown via context cancellation.
var ErrServerClosed = errors.New("doq: server closed")

// Server is an immutable configuration carrier for a DoQ server.
type Server struct {
	addr    netip.AddrPort
	handler acidns.Handler
	cfg     serverConfig
}

// NewServer validates the configuration. It does NOT bind a socket;
// pass the result to [Server.Run] to start serving. tls.Config is
// required (DoQ runs over QUIC which mandates TLS); the server
// raises MinVersion to TLS 1.3 when unset and appends the "doq"
// ALPN identifier.
func NewServer(addr netip.AddrPort, h acidns.Handler, opts ...ServerOption) (*Server, error) {
	if h == nil {
		return nil, fmt.Errorf("doq: handler is nil")
	}
	cfg := serverConfig{
		idleTimeout:    30 * time.Second,
		writeTimeout:   5 * time.Second,
		maxMessageSize: 16 * 1024,
		maxStreamsPer:  256,
	}
	for _, o := range opts {
		o.applyDoQServer(&cfg)
	}
	if cfg.tlsConfig == nil {
		return nil, fmt.Errorf("doq: WithServerTLSConfig is required")
	}
	tc := cfg.tlsConfig.Clone()
	if tc.MinVersion == 0 {
		tc.MinVersion = tls.VersionTLS13
	}
	if !slices.Contains(tc.NextProtos, alpn) {
		tc.NextProtos = append(tc.NextProtos, alpn)
	}
	cfg.tlsConfig = tc
	return &Server{addr: addr, handler: h, cfg: cfg}, nil
}

// Run binds a fresh UDP socket, layers QUIC on top, and serves DoQ
// streams until ctx is cancelled.
func (s *Server) Run(ctx context.Context) (*Controller, error) {
	pc, err := net.ListenPacket("udp", s.addr.String()) //nolint:noctx // socket lifetime is bound to Run's ctx
	if err != nil {
		return nil, fmt.Errorf("doq: listen %s: %w", s.addr, err)
	}
	ua, ok := pc.LocalAddr().(*net.UDPAddr)
	if !ok {
		_ = pc.Close()
		return nil, fmt.Errorf("doq: listen %s: unexpected addr type %T", s.addr, pc.LocalAddr())
	}
	bound := netip.AddrPortFrom(ua.AddrPort().Addr(), uint16(ua.Port))

	ln, err := quic.Listen(pc, s.cfg.tlsConfig, &quic.Config{
		MaxIdleTimeout:    s.cfg.idleTimeout,
		MaxIncomingStreams: int64(s.cfg.maxStreamsPer),
	})
	if err != nil {
		_ = pc.Close()
		return nil, fmt.Errorf("doq: quic listen: %w", err)
	}

	loop := &serverLoop{
		ln:      ln,
		addr:    bound,
		handler: s.handler,
		cfg:     s.cfg,
	}
	ctrl := &Controller{addr: bound, done: make(chan struct{})}
	go func() {
		defer close(ctrl.done)
		err := loop.run(ctx)
		if err != nil && !errors.Is(err, ErrServerClosed) {
			ctrl.setErr(err)
		}
	}()
	return ctrl, nil
}

// Controller is the runtime handle returned by [Server.Run].
type Controller struct {
	addr netip.AddrPort
	done chan struct{}
	err  atomic.Pointer[error]
}

// Addr returns the bound UDP address.
func (c *Controller) Addr() netip.AddrPort { return c.addr }

// Done closes when the work goroutine has exited.
func (c *Controller) Done() <-chan struct{} { return c.done }

// Err returns the terminal error, or nil after a clean shutdown.
func (c *Controller) Err() error {
	if p := c.err.Load(); p != nil {
		return *p
	}
	return nil
}

// Wait blocks until the server has shut down.
func (c *Controller) Wait() error {
	<-c.done
	return c.Err()
}

func (c *Controller) setErr(err error) {
	if err != nil {
		c.err.Store(&err)
	}
}

type serverLoop struct {
	ln      *quic.Listener
	addr    netip.AddrPort
	handler acidns.Handler
	cfg     serverConfig
	wg      sync.WaitGroup
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

	for {
		conn, err := l.ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, quic.ErrServerClosed) {
				return ErrServerClosed
			}
			return fmt.Errorf("doq: accept: %w", err)
		}
		l.wg.Add(1)
		go func(c *quic.Conn) {
			defer l.wg.Done()
			l.serveConn(ctx, c)
		}(conn)
	}
}

func (l *serverLoop) serveConn(ctx context.Context, conn *quic.Conn) {
	defer func() { _ = conn.CloseWithError(0, "") }()

	remote := remoteAddrFromConn(conn)
	var streamWg sync.WaitGroup
	defer streamWg.Wait()

	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		streamWg.Add(1)
		go func(s *quic.Stream) {
			defer streamWg.Done()
			l.serveStream(ctx, s, remote)
		}(stream)
	}
}

func remoteAddrFromConn(c *quic.Conn) netip.AddrPort {
	if ua, ok := c.RemoteAddr().(*net.UDPAddr); ok {
		return ua.AddrPort()
	}
	ap, _ := netip.ParseAddrPort(c.RemoteAddr().String())
	return ap
}

func (l *serverLoop) serveStream(ctx context.Context, stream *quic.Stream, remote netip.AddrPort) {
	defer func() { _ = stream.Close() }()

	if l.cfg.idleTimeout > 0 {
		_ = stream.SetReadDeadline(time.Now().Add(l.cfg.idleTimeout))
	}

	var hdr [2]byte
	if _, err := io.ReadFull(stream, hdr[:]); err != nil {
		return
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if l.cfg.maxMessageSize > 0 && n > l.cfg.maxMessageSize {
		stream.CancelRead(0)
		return
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(stream, body); err != nil {
		return
	}
	q, err := wire.Unmarshal(body)
	if err != nil {
		return
	}
	// RFC 9250 §4.2.1: clients MUST set the wire ID to 0; servers
	// SHOULD reject anything else. Drop the stream silently rather
	// than reply with FORMERR — a non-zero ID is a strong signal of
	// a misbehaving or wrong-protocol client.
	if q.ID() != 0 {
		stream.CancelRead(0)
		return
	}

	w := &responseWriter{
		stream:       stream,
		remote:       remote,
		local:        l.addr,
		writeTimeout: l.cfg.writeTimeout,
	}
	l.handler.ServeDNS(ctx, w, q)
}

type responseWriter struct {
	stream       *quic.Stream
	remote       netip.AddrPort
	local        netip.AddrPort
	writeTimeout time.Duration
	wrote        bool
	mu           sync.Mutex
}

func (w *responseWriter) RemoteAddr() netip.AddrPort { return w.remote }
func (w *responseWriter) LocalAddr() netip.AddrPort  { return w.local }
func (w *responseWriter) Network() string            { return "doq" }

func (w *responseWriter) WriteMsg(m wire.Message) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.wrote {
		return fmt.Errorf("doq: WriteMsg called twice on a single stream")
	}
	w.wrote = true

	buf, err := wire.Marshal(m)
	if err != nil {
		return err
	}
	if len(buf) > 0xffff {
		return fmt.Errorf("doq: response exceeds 65535 bytes")
	}
	// RFC 9250 §4.2.1: server response wire ID MUST be 0. Clients
	// expect this; our handler echoes the request ID (which the
	// stream loop already enforced as 0), so this is a defensive
	// check rather than a correction.
	if len(buf) >= 2 {
		buf[0] = 0
		buf[1] = 0
	}

	if w.writeTimeout > 0 {
		_ = w.stream.SetWriteDeadline(time.Now().Add(w.writeTimeout))
		defer func() { _ = w.stream.SetWriteDeadline(time.Time{}) }()
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(buf)))
	if _, err := w.stream.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.stream.Write(buf)
	return err
}
