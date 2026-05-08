package acidns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/lestrrat-go/acidns/wire"
)

// TCPListenerOption configures a TCP server.
type TCPListenerOption interface{ applyTCPServer(*tcpListenerConfig) }

type tcpListenerOptionFunc func(*tcpListenerConfig)

func (f tcpListenerOptionFunc) applyTCPServer(c *tcpListenerConfig) { f(c) }

type tcpListenerConfig struct {
	idleTimeout       time.Duration
	writeTimeout      time.Duration
	maxConnections    int
	maxMessageSize    int
	maxQueriesPerConn int
	maxConnLifetime   time.Duration
	maxInflightPer    int
}

// WithTCPIdleTimeout sets how long an idle connection is kept open between
// queries. RFC 7766 §6.5 recommends a few seconds; the default is 10s.
// A non-positive value disables the idle timeout.
func WithTCPIdleTimeout(d time.Duration) TCPListenerOption {
	return tcpListenerOptionFunc(func(c *tcpListenerConfig) { c.idleTimeout = d })
}

// WithTCPWriteTimeout caps how long a single response write may take.
// Without a write deadline a slow-read attacker (TCP receive window 0)
// can pin a server goroutine indefinitely. Default 5s; non-positive
// disables the deadline.
func WithTCPWriteTimeout(d time.Duration) TCPListenerOption {
	return tcpListenerOptionFunc(func(c *tcpListenerConfig) { c.writeTimeout = d })
}

// WithTCPMaxConnections caps the number of concurrent TCP connections.
// Once the cap is reached the accept loop blocks until a slot frees,
// providing natural backpressure via the kernel's TCP listen backlog.
// A non-positive value disables the cap. Defaults to 1024.
func WithTCPMaxConnections(n int) TCPListenerOption {
	return tcpListenerOptionFunc(func(c *tcpListenerConfig) { c.maxConnections = n })
}

// WithTCPMaxMessageSize caps the length-prefixed body the server is
// willing to read from a single TCP query. The 16-bit length prefix
// permits up to 65535 bytes per message; without a tighter ceiling, a
// hostile client can force the server to allocate a 64 KiB buffer per
// connection. Default 16 KiB — wide enough for the largest envelopes
// the bundled AXFR chunker emits while keeping per-connection memory
// bounded. A non-positive value disables the cap (allows up to 65535).
func WithTCPMaxMessageSize(n int) TCPListenerOption {
	return tcpListenerOptionFunc(func(c *tcpListenerConfig) { c.maxMessageSize = n })
}

// WithTCPMaxQueriesPerConn caps the total queries served on a single
// connection before it is closed. Mitigates a peer that holds a slot
// indefinitely at idle-timeout cadence. A non-positive value disables
// the cap. Defaults to 0 (no cap).
func WithTCPMaxQueriesPerConn(n int) TCPListenerOption {
	return tcpListenerOptionFunc(func(c *tcpListenerConfig) { c.maxQueriesPerConn = n })
}

// WithTCPMaxConnLifetime caps wall-clock time a single connection may
// remain open. Backstop for misbehaving peers and a way to cycle TLS
// session state on a sane cadence. A non-positive value disables the
// cap. Defaults to 0 (no cap).
func WithTCPMaxConnLifetime(d time.Duration) TCPListenerOption {
	return tcpListenerOptionFunc(func(c *tcpListenerConfig) { c.maxConnLifetime = d })
}

// WithTCPMaxInflightPerConn caps the number of concurrently-running
// handler goroutines per connection. Pipelined responses (RFC 7766
// §6.2.1.1) may be returned out of order; this cap prevents a single
// connection from spawning unbounded handler goroutines if the peer
// pushes queries faster than they complete. Defaults to 32; a
// non-positive value disables pipelining (handlers run serially).
func WithTCPMaxInflightPerConn(n int) TCPListenerOption {
	return tcpListenerOptionFunc(func(c *tcpListenerConfig) { c.maxInflightPer = n })
}

type tcpListener struct {
	ln        net.Listener
	addr      netip.AddrPort
	handler   Handler
	cfg       tcpListenerConfig
	sem       chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
	bodyPool  sync.Pool

	handlerCtx    context.Context
	handlerCancel context.CancelFunc
}

// ListenTCP binds a TCP socket on addr and returns a Server. Each
// connection is dispatched to a goroutine that loops reading
// length-prefixed queries (RFC 1035 §4.2.2) and writing length-prefixed
// responses (RFC 7766). Handlers run concurrently per-connection so
// responses may be returned in any order (pipelining).
func ListenTCP(addr netip.AddrPort, h Handler, opts ...TCPListenerOption) (Server, error) {
	if h == nil {
		return nil, fmt.Errorf("dnsserver: handler is nil")
	}
	cfg := tcpListenerConfig{
		idleTimeout:    10 * time.Second,
		writeTimeout:   5 * time.Second,
		maxConnections: 1024,
		maxMessageSize: 16 * 1024,
		maxInflightPer: 32,
	}
	for _, o := range opts {
		o.applyTCPServer(&cfg)
	}
	ln, err := net.Listen("tcp", addr.String()) //nolint:noctx // listen lifetime is bound to Serve, not the caller's ctx
	if err != nil {
		return nil, fmt.Errorf("dnsserver: tcp listen %s: %w", addr, err)
	}
	la, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		_ = ln.Close()
		return nil, fmt.Errorf("dnsserver: tcp listen %s: unexpected addr type %T", addr, ln.Addr())
	}
	hctx, hcancel := context.WithCancel(context.Background())
	bufSize := cfg.maxMessageSize
	if bufSize <= 0 {
		bufSize = 65535
	}
	l := &tcpListener{
		ln:            ln,
		addr:          netip.AddrPortFrom(la.AddrPort().Addr(), uint16(la.Port)),
		handler:       h,
		cfg:           cfg,
		handlerCtx:    hctx,
		handlerCancel: hcancel,
	}
	l.bodyPool.New = func() any {
		b := make([]byte, bufSize)
		return &b
	}
	if cfg.maxConnections > 0 {
		l.sem = make(chan struct{}, cfg.maxConnections)
	}
	return l, nil
}

func (s *tcpListener) Addr() netip.AddrPort { return s.addr }

// Shutdown closes the listener and cancels the handler context so per-
// connection goroutines see deadlines fire on idle-but-open sockets,
// then waits for in-flight per-connection goroutines to finish. If ctx
// expires before that happens, the context error is returned.
func (s *tcpListener) Shutdown(ctx context.Context) error {
	s.closeOnce.Do(func() {
		s.handlerCancel()
		_ = s.ln.Close()
	})
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *tcpListener) Serve(ctx context.Context) error {
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			s.handlerCancel()
			_ = s.ln.Close()
		case <-s.handlerCtx.Done():
			_ = s.ln.Close()
		case <-stop:
		}
	}()

	// Backoff bounds for transient Accept errors (e.g. EMFILE/ENFILE
	// from process or kernel FD exhaustion). The pattern mirrors the
	// canonical net/http.Server.Serve loop: never terminate Serve on
	// recoverable errors, sleep with capped exponential backoff and
	// retry; the kernel listen backlog absorbs queued SYNs while we
	// wait.
	const acceptBackoffStart = 5 * time.Millisecond
	const acceptBackoffCap = time.Second
	tempBackoff := time.Duration(0)

	for {
		if s.sem != nil {
			select {
			case s.sem <- struct{}{}:
			case <-ctx.Done():
				_ = s.ln.Close()
				s.wg.Wait()
				return ErrServerClosed
			}
		}
		conn, err := s.ln.Accept()
		if err != nil {
			if s.sem != nil {
				<-s.sem
			}
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				s.wg.Wait()
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
					_ = s.ln.Close()
					s.wg.Wait()
					return ErrServerClosed
				}
				continue
			}
			s.wg.Wait()
			return fmt.Errorf("dnsserver: tcp accept: %w", err)
		}
		tempBackoff = 0
		s.wg.Add(1)
		go func(c net.Conn) {
			defer func() {
				if s.sem != nil {
					<-s.sem
				}
				s.wg.Done()
			}()
			s.serveConn(c)
		}(conn)
	}
}

// isAcceptTransient reports whether err is a transient Accept failure
// that should not terminate the Serve loop. Uses errors.Is on the
// kernel-resource exhaustion modes; falls back to net.OpError's
// underlying syscall.Errno comparison so we don't rely on locale-
// dependent error string substrings.
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

// remoteAddrFromConn returns the connection's remote address as a
// netip.AddrPort. We prefer net.TCPAddr.AddrPort() over re-parsing the
// String() form because the latter silently returns the zero AddrPort
// on unexpected formats, which would let per-source policies (ACL,
// rate limit) bucket all such peers together.
func remoteAddrFromConn(c net.Conn) netip.AddrPort {
	if ta, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return ta.AddrPort()
	}
	ap, _ := netip.ParseAddrPort(c.RemoteAddr().String())
	return ap
}

func (s *tcpListener) serveConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	// Per-connection context derived from the listener-wide handlerCtx.
	// Cancelling connCtx propagates to in-flight handlers.
	connCtx, connCancel := context.WithCancel(s.handlerCtx)
	defer connCancel()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-s.handlerCtx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-stop:
		}
	}()

	// Optional connection-lifetime cap: backstop for misbehaving peers
	// and a way to recycle TLS session state.
	var lifetimeDeadline time.Time
	if s.cfg.maxConnLifetime > 0 {
		lifetimeDeadline = time.Now().Add(s.cfg.maxConnLifetime)
	}

	remote := remoteAddrFromConn(conn)

	// Writer mutex serialises framed responses across pipelined handler
	// goroutines so two concurrent writes can't interleave length
	// prefixes and bodies.
	var writeMu sync.Mutex

	// Per-connection handler concurrency cap. Bounds goroutine count
	// when a peer pushes queries faster than handlers complete.
	var perConnSem chan struct{}
	if s.cfg.maxInflightPer > 0 {
		perConnSem = make(chan struct{}, s.cfg.maxInflightPer)
	}
	var connWg sync.WaitGroup
	defer connWg.Wait()

	queries := 0
	for {
		if !lifetimeDeadline.IsZero() && time.Now().After(lifetimeDeadline) {
			return
		}
		if s.cfg.maxQueriesPerConn > 0 && queries >= s.cfg.maxQueriesPerConn {
			return
		}

		readDeadline := time.Time{}
		if s.cfg.idleTimeout > 0 {
			readDeadline = time.Now().Add(s.cfg.idleTimeout)
		}
		if !lifetimeDeadline.IsZero() && (readDeadline.IsZero() || lifetimeDeadline.Before(readDeadline)) {
			readDeadline = lifetimeDeadline
		}
		if !readDeadline.IsZero() {
			_ = conn.SetReadDeadline(readDeadline)
		}

		var hdr [2]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return // EOF or idle timeout — close the connection
		}
		n := int(binary.BigEndian.Uint16(hdr[:]))
		if s.cfg.maxMessageSize > 0 && n > s.cfg.maxMessageSize {
			// Hostile or misconfigured peer — close the connection
			// rather than allocate up to 64 KiB. The 16-bit length
			// prefix is fixed by the wire format; the only defense
			// is to refuse oversized claims at the read boundary.
			return
		}

		bufp, _ := s.bodyPool.Get().(*[]byte)
		body := (*bufp)[:n]
		if _, err := io.ReadFull(conn, body); err != nil {
			s.bodyPool.Put(bufp)
			return
		}
		queries++

		// Acquire per-conn slot. If we'd block, wait — pipelining is a
		// best-effort acceleration and the read-loop blocking is fine.
		if perConnSem != nil {
			select {
			case perConnSem <- struct{}{}:
			case <-connCtx.Done():
				s.bodyPool.Put(bufp)
				return
			}
		}
		connWg.Add(1)
		go func(bufp *[]byte, n int) {
			defer func() {
				s.bodyPool.Put(bufp)
				if perConnSem != nil {
					<-perConnSem
				}
				connWg.Done()
			}()
			body := (*bufp)[:n]
			q, err := wire.Unmarshal(body)
			if err != nil {
				return // malformed — drop, do not close conn from worker
			}
			w := &tcpResponseWriter{
				conn:         conn,
				remote:       remote,
				local:        s.addr,
				writeTimeout: s.cfg.writeTimeout,
				writeMu:      &writeMu,
			}
			s.handler.ServeDNS(contextWithRawRequest(connCtx, body), w, q)
		}(bufp, n)
	}
}

type tcpResponseWriter struct {
	conn         net.Conn
	remote       netip.AddrPort
	local        netip.AddrPort
	writeTimeout time.Duration
	writeMu      *sync.Mutex
}

func (w *tcpResponseWriter) RemoteAddr() netip.AddrPort { return w.remote }
func (w *tcpResponseWriter) LocalAddr() netip.AddrPort  { return w.local }
func (w *tcpResponseWriter) Network() string            { return "tcp" }

func (w *tcpResponseWriter) WriteMsg(m wire.Message) error {
	buf, err := wire.Marshal(m)
	if err != nil {
		return err
	}
	if len(buf) > 0xffff {
		return fmt.Errorf("dnsserver: tcp response exceeds 65535 bytes")
	}
	// Slow-read protection: a peer that opens the TCP receive window to
	// zero can otherwise pin this goroutine forever. RFC 7766 has no
	// guidance here; net/http uses 5–30 s for analogous cases.
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
