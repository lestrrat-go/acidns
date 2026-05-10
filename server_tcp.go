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

	"github.com/lestrrat-go/acidns/internal/serverctl"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/option/v3"
)

// TCPListenerOption configures a TCP server.
type TCPListenerOption interface {
	option.Interface
	tcpListenerOption()
}

type tcpListenerOption struct{ option.Interface }

func (tcpListenerOption) tcpListenerOption() {}

type tcpListenerConfig struct {
	idleTimeout        time.Duration
	writeTimeout       time.Duration
	messageReadTimeout time.Duration
	maxConnections     int
	maxConnsPerSource  int
	maxMessageSize     int
	maxQueriesPerConn  int
	maxConnLifetime    time.Duration
	maxInflightPer     int
}

type identTCPIdleTimeout struct{}
type identTCPWriteTimeout struct{}
type identTCPMaxConnections struct{}
type identTCPMaxConnsPerSource struct{}
type identTCPMaxMessageSize struct{}
type identTCPMaxQueriesPerConn struct{}
type identTCPMaxConnLifetime struct{}
type identTCPMessageReadTimeout struct{}
type identTCPMaxInflightPerConn struct{}

// WithTCPIdleTimeout sets how long an idle connection is kept open between
// queries. RFC 7766 §6.5 recommends a few seconds; the default is 10s.
// A non-positive value disables the idle timeout.
func WithTCPIdleTimeout(d time.Duration) TCPListenerOption {
	return tcpListenerOption{option.New(identTCPIdleTimeout{}, d)}
}

// WithTCPWriteTimeout caps how long a single response write may take.
// Without a write deadline a slow-read attacker (TCP receive window 0)
// can pin a server goroutine indefinitely. Default 5s; non-positive
// disables the deadline.
func WithTCPWriteTimeout(d time.Duration) TCPListenerOption {
	return tcpListenerOption{option.New(identTCPWriteTimeout{}, d)}
}

// WithTCPMaxConnections caps the number of concurrent TCP connections.
// Once the cap is reached the accept loop blocks until a slot frees,
// providing natural backpressure via the kernel's TCP listen backlog.
// A non-positive value disables the cap. Defaults to 1024.
func WithTCPMaxConnections(n int) TCPListenerOption {
	return tcpListenerOption{option.New(identTCPMaxConnections{}, n)}
}

// WithTCPMaxConnsPerSource caps the number of concurrent TCP
// connections originating from a single remote IP (canonicalised via
// netip.Addr.Unmap so v4-mapped v6 addresses share a bucket with their
// v4 counterpart). Without this cap a single peer can occupy every slot
// permitted by [WithTCPMaxConnections] and starve all other sources.
// On exceeding the cap the new connection is closed immediately and the
// accept loop continues. A non-positive value disables the per-source
// cap. Defaults to 32 — high enough that a well-behaved client running
// many parallel queries from one host is never affected, low enough
// that a hostile peer cannot starve the listener.
func WithTCPMaxConnsPerSource(n int) TCPListenerOption {
	return tcpListenerOption{option.New(identTCPMaxConnsPerSource{}, n)}
}

// WithTCPMaxMessageSize caps the length-prefixed body the server is
// willing to read from a single TCP query. The 16-bit length prefix
// permits up to 65535 bytes per message; without a tighter ceiling, a
// hostile client can force the server to allocate a 64 KiB buffer per
// connection. Default 16 KiB — wide enough for the largest envelopes
// the bundled AXFR chunker emits while keeping per-connection memory
// bounded. A non-positive value disables the cap (allows up to 65535).
func WithTCPMaxMessageSize(n int) TCPListenerOption {
	return tcpListenerOption{option.New(identTCPMaxMessageSize{}, n)}
}

// WithTCPMaxQueriesPerConn caps the total queries served on a single
// connection before it is closed. Mitigates a peer that holds a slot
// indefinitely at idle-timeout cadence. A non-positive value disables
// the cap. Defaults to 10000 — high enough that a well-behaved RFC
// 7766 client reusing the connection is never affected, low enough
// that a peer cannot pin a slot through arbitrarily many trickled
// queries. Operators MUST tune this for unusual workloads (long-lived
// internal mirrors, AXFR-heavy backplanes).
func WithTCPMaxQueriesPerConn(n int) TCPListenerOption {
	return tcpListenerOption{option.New(identTCPMaxQueriesPerConn{}, n)}
}

// WithTCPMaxConnLifetime caps wall-clock time a single connection may
// remain open. Backstop for misbehaving peers and a way to cycle TLS
// session state on a sane cadence. A non-positive value disables the
// cap. Defaults to 1 hour. Operators MUST tune this for workloads that
// rely on multi-hour streams (e.g. long-lived internal AXFR mirrors).
func WithTCPMaxConnLifetime(d time.Duration) TCPListenerOption {
	return tcpListenerOption{option.New(identTCPMaxConnLifetime{}, d)}
}

// WithTCPMessageReadTimeout caps how long the server will wait for the
// body bytes of a single message after the 2-byte length prefix has
// arrived. The idle timeout ([WithTCPIdleTimeout]) governs the wait
// between messages; once a length prefix is in hand the peer is
// committed to delivering the body promptly, so this deadline is
// tighter. Without this distinction a peer that sends the prefix and
// then drips body bytes just under the idle interval can pin a slot
// for hours (idle * maxQueriesPerConn). Default 5s; non-positive
// disables the per-message deadline (falls back to the idle timeout
// for the body read as well).
func WithTCPMessageReadTimeout(d time.Duration) TCPListenerOption {
	return tcpListenerOption{option.New(identTCPMessageReadTimeout{}, d)}
}

// WithTCPMaxInflightPerConn caps the number of concurrently-running
// handler goroutines per connection. Pipelined responses (RFC 7766
// §6.2.1.1) may be returned out of order; this cap prevents a single
// connection from spawning unbounded handler goroutines if the peer
// pushes queries faster than they complete. Defaults to 32; a
// non-positive value disables pipelining (handlers run serially).
func WithTCPMaxInflightPerConn(n int) TCPListenerOption {
	return tcpListenerOption{option.New(identTCPMaxInflightPerConn{}, n)}
}

// TCPServer is an immutable configuration holder for a TCP DNS server.
// It carries the listen address, the Handler, and applied options;
// it does NOT carry runtime state. Call [TCPServer.Run] to spawn an
// independent server instance — the same TCPServer may be Run any
// number of times to spawn parallel instances. The running instance
// is reachable only through the returned [*TCPController].
type TCPServer struct {
	addr    netip.AddrPort
	handler Handler
	cfg     tcpListenerConfig
}

// NewTCPServer validates the configuration. It does NOT bind a socket;
// pass the result to Run when you're ready to start serving. The
// returned value is safe to share across goroutines and may be Run
// multiple times to spawn multiple independent server instances.
func NewTCPServer(addr netip.AddrPort, h Handler, opts ...TCPListenerOption) (*TCPServer, error) {
	if h == nil {
		return nil, fmt.Errorf("acidns: handler is nil")
	}
	if !addr.IsValid() {
		return nil, fmt.Errorf("acidns: invalid bind address")
	}
	cfg := tcpListenerConfig{
		idleTimeout:        10 * time.Second,
		writeTimeout:       5 * time.Second,
		messageReadTimeout: 5 * time.Second,
		maxConnections:     1024,
		maxConnsPerSource:  32,
		maxMessageSize:     16 * 1024,
		maxInflightPer:     32,
		maxQueriesPerConn:  10000,
		maxConnLifetime:    time.Hour,
	}
	for _, o := range opts {
		switch o.Ident() {
		case identTCPIdleTimeout{}:
			cfg.idleTimeout = option.MustGet[time.Duration](o)
		case identTCPWriteTimeout{}:
			cfg.writeTimeout = option.MustGet[time.Duration](o)
		case identTCPMaxConnections{}:
			cfg.maxConnections = option.MustGet[int](o)
		case identTCPMaxConnsPerSource{}:
			cfg.maxConnsPerSource = option.MustGet[int](o)
		case identTCPMaxMessageSize{}:
			cfg.maxMessageSize = option.MustGet[int](o)
		case identTCPMaxQueriesPerConn{}:
			cfg.maxQueriesPerConn = option.MustGet[int](o)
		case identTCPMaxConnLifetime{}:
			cfg.maxConnLifetime = option.MustGet[time.Duration](o)
		case identTCPMessageReadTimeout{}:
			cfg.messageReadTimeout = option.MustGet[time.Duration](o)
		case identTCPMaxInflightPerConn{}:
			cfg.maxInflightPer = option.MustGet[int](o)
		}
	}
	return &TCPServer{addr: addr, handler: h, cfg: cfg}, nil
}

// Run binds a fresh TCP socket and spawns a new accept-and-dispatch
// goroutine. Each call constructs an independent server instance;
// the receiver holds only configuration and is unchanged by Run. The
// returned TCPController is the sole handle to the new instance: it
// exposes the bound address (which may differ from the requested
// address when port=0) and a Done channel that closes once the loop
// has exited cleanly. Cancel ctx to stop the instance; the goroutine
// drains in-flight per-connection goroutines before closing.
func (s *TCPServer) Run(ctx context.Context) (*TCPController, error) {
	ln, err := net.Listen("tcp", s.addr.String()) //nolint:noctx // socket lifetime is bound to Run's ctx, not the bind call
	if err != nil {
		return nil, fmt.Errorf("acidns: tcp listen %s: %w", s.addr, err)
	}
	la, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		_ = ln.Close()
		return nil, fmt.Errorf("acidns: tcp listen %s: unexpected addr type %T", s.addr, ln.Addr())
	}
	bound := netip.AddrPortFrom(la.AddrPort().Addr(), uint16(la.Port))

	bufSize := s.cfg.maxMessageSize
	if bufSize <= 0 {
		bufSize = 65535
	}
	loop := &tcpLoop{
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

	ctrl := &TCPController{Core: serverctl.New(bound)}
	go func() {
		defer ctrl.CloseDone()
		err := loop.run(ctx)
		if err != nil && !errors.Is(err, ErrServerClosed) {
			ctrl.SetErr(err)
		}
	}()
	return ctrl, nil
}

// tcpLoop owns the runtime state of a serving TCP listener.
type tcpLoop struct {
	ln       net.Listener
	addr     netip.AddrPort
	handler  Handler
	cfg      tcpListenerConfig
	sem      chan struct{}
	wg       sync.WaitGroup
	bodyPool sync.Pool

	// perSourceMu guards perSource. Keyed on netip.Addr.Unmap so a
	// v4-mapped v6 client shares a bucket with its v4 form.
	perSourceMu sync.Mutex
	perSource   map[netip.Addr]int
}

// reservePerSource increments the per-source counter if the cap permits
// and returns true. When the cap would be exceeded it returns false and
// the caller must close the connection without spawning a goroutine.
func (l *tcpLoop) reservePerSource(addr netip.Addr) bool {
	if l.cfg.maxConnsPerSource <= 0 {
		return true
	}
	addr = addr.Unmap()
	l.perSourceMu.Lock()
	defer l.perSourceMu.Unlock()
	if l.perSource[addr] >= l.cfg.maxConnsPerSource {
		return false
	}
	if l.perSource == nil {
		l.perSource = make(map[netip.Addr]int)
	}
	l.perSource[addr]++
	return true
}

// releasePerSource decrements the counter for addr; the entry is
// removed when the count reaches zero so the map does not grow without
// bound across the lifetime of the listener.
func (l *tcpLoop) releasePerSource(addr netip.Addr) {
	if l.cfg.maxConnsPerSource <= 0 {
		return
	}
	addr = addr.Unmap()
	l.perSourceMu.Lock()
	defer l.perSourceMu.Unlock()
	if l.perSource[addr] <= 1 {
		delete(l.perSource, addr)
		return
	}
	l.perSource[addr]--
}

func (l *tcpLoop) run(ctx context.Context) error {
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
			return fmt.Errorf("acidns: tcp accept: %w", err)
		}
		tempBackoff = 0
		remote := remoteAddrFromConn(conn)
		if !l.reservePerSource(remote.Addr()) {
			_ = conn.Close()
			if l.sem != nil {
				<-l.sem
			}
			continue
		}
		l.wg.Add(1)
		go func(c net.Conn, src netip.Addr) {
			defer func() {
				l.releasePerSource(src)
				if l.sem != nil {
					<-l.sem
				}
				l.wg.Done()
			}()
			l.serveConn(ctx, c)
		}(conn, remote.Addr())
	}
}

// isAcceptTransient reports whether err is a transient Accept failure
// that should not terminate the Serve loop. Uses errors.Is on the
// kernel-resource exhaustion modes so we don't rely on locale-
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

func (l *tcpLoop) serveConn(ctx context.Context, conn net.Conn) {
	// LIFO-load-bearing: this defer must come BEFORE the connWg.Wait
	// defer below. defers run LIFO so connWg.Wait runs first (handler
	// goroutines drain), THEN conn.Close. Reordering would let
	// pipelined handler writes hit a closed conn.
	defer func() { _ = conn.Close() }()

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

	remote := remoteAddrFromConn(conn)

	// Writer mutex serialises framed responses across pipelined handler
	// goroutines so two concurrent writes can't interleave length
	// prefixes and bodies.
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
			return // EOF or idle timeout — close the connection
		}
		n := int(binary.BigEndian.Uint16(hdr[:]))
		if l.cfg.maxMessageSize > 0 && n > l.cfg.maxMessageSize {
			return
		}

		// Once the length prefix has arrived, the peer is committed to
		// delivering the body promptly. Tighten the read deadline to
		// messageReadTimeout so a peer cannot drip body bytes at the
		// idle-interval cadence and pin a slot for hours. Still respect
		// the lifetime cap.
		bodyDeadline := time.Time{}
		if l.cfg.messageReadTimeout > 0 {
			bodyDeadline = time.Now().Add(l.cfg.messageReadTimeout)
		}
		if !lifetimeDeadline.IsZero() && (bodyDeadline.IsZero() || lifetimeDeadline.Before(bodyDeadline)) {
			bodyDeadline = lifetimeDeadline
		}
		if !bodyDeadline.IsZero() {
			_ = conn.SetReadDeadline(bodyDeadline)
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
			w := &tcpResponseWriter{
				conn:         conn,
				remote:       remote,
				local:        l.addr,
				writeTimeout: l.cfg.writeTimeout,
				writeMu:      &writeMu,
			}
			switch verdict, reply := PreflightRequest(q); verdict {
			case PreflightDrop:
				return
			case PreflightReply:
				_ = w.WriteMsg(reply)
				return
			}
			l.handler.ServeDNS(contextWithRawRequest(connCtx, body), w, q)
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
		return fmt.Errorf("acidns: tcp response exceeds 65535 bytes")
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
