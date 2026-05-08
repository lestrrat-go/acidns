package acidns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/acidns/wire"
)

// TCPListenerOption configures a TCP server.
type TCPListenerOption interface{ applyTCPServer(*tcpListenerConfig) }

type tcpListenerOptionFunc func(*tcpListenerConfig)

func (f tcpListenerOptionFunc) applyTCPServer(c *tcpListenerConfig) { f(c) }

type tcpListenerConfig struct {
	idleTimeout    time.Duration
	writeTimeout   time.Duration
	maxConnections int
	maxMessageSize int
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

type tcpListener struct {
	ln        net.Listener
	addr      netip.AddrPort
	handler   Handler
	cfg       tcpListenerConfig
	sem       chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
}

// ListenTCP binds a TCP socket on addr and returns a Server. Each
// connection is dispatched to a goroutine that loops reading
// length-prefixed queries (RFC 1035 §4.2.2) and writing length-prefixed
// responses (RFC 7766).
func ListenTCP(addr netip.AddrPort, h Handler, opts ...TCPListenerOption) (Server, error) {
	if h == nil {
		return nil, fmt.Errorf("dnsserver: handler is nil")
	}
	cfg := tcpListenerConfig{
		idleTimeout:    10 * time.Second,
		writeTimeout:   5 * time.Second,
		maxConnections: 1024,
		maxMessageSize: 16 * 1024,
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
	l := &tcpListener{
		ln:      ln,
		addr:    netip.AddrPortFrom(la.AddrPort().Addr(), uint16(la.Port)),
		handler: h,
		cfg:     cfg,
	}
	if cfg.maxConnections > 0 {
		l.sem = make(chan struct{}, cfg.maxConnections)
	}
	return l, nil
}

func (s *tcpListener) Addr() netip.AddrPort { return s.addr }

// Shutdown closes the listener and any pending connection deadlines so
// Serve returns ErrServerClosed, then waits for in-flight per-connection
// goroutines to finish. If ctx expires before that happens, the context
// error is returned.
func (s *tcpListener) Shutdown(ctx context.Context) error {
	s.closeOnce.Do(func() { _ = s.ln.Close() })
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
			s.serveConn(ctx, c)
		}(conn)
	}
}

// isAcceptTransient reports whether err is a transient Accept failure
// that should not terminate the Serve loop. The standard library
// removed the Temporary() distinction, so we substring-match the
// well-known kernel exhaustion modes — the same approach
// net/http.Server.Serve takes today.
func isAcceptTransient(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, s := range []string{
		"too many open files",
		"file table overflow",
		"resource temporarily unavailable",
	} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

func (s *tcpListener) serveConn(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()

	// Cancel pending I/O when the server context is cancelled, and tear
	// down per-request contexts so handlers chasing upstreams don't keep
	// running after this connection has gone away.
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

	remote, _ := netip.ParseAddrPort(conn.RemoteAddr().String())

	for {
		if s.cfg.idleTimeout > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(s.cfg.idleTimeout))
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
		body := make([]byte, n)
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}

		q, err := wire.Unmarshal(body)
		if err != nil {
			return // malformed — close
		}

		w := &tcpResponseWriter{conn: conn, remote: remote, local: s.addr, writeTimeout: s.cfg.writeTimeout}
		s.handler.ServeDNS(contextWithRawRequest(connCtx, body), w, q)
	}
}

type tcpResponseWriter struct {
	conn         net.Conn
	remote       netip.AddrPort
	local        netip.AddrPort
	writeTimeout time.Duration
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
