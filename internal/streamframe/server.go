package streamframe

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/lestrrat-go/acidns/internal/netutil"
	"github.com/lestrrat-go/acidns/wire"
)

// ErrServerClosed is returned by [LoopConfig.Run] when the loop exits
// because ctx was cancelled or the underlying listener was closed for
// an expected reason. Transport packages alias their own
// ErrServerClosed to this value (or to acidns.ErrServerClosed) so
// errors.Is matches the canonical sentinel.
var ErrServerClosed = errors.New("streamframe: server closed")

// Dispatcher handles a single decoded query on a length-framed
// connection. The framework hands the dispatcher a ResponseWriter that
// already serialises framed writes across pipelined goroutines on the
// same connection, a parsed query, and the raw wire bytes (which TSIG
// / SIG(0) verifiers sign over). raw is owned by the framework — it is
// recycled to a sync.Pool as soon as Dispatch returns, so a dispatcher
// MUST copy it if a child goroutine needs it past return.
type Dispatcher interface {
	Dispatch(ctx context.Context, w *ResponseWriter, q wire.Message, raw []byte)
}

// DispatcherFunc adapts a plain function into a [Dispatcher].
type DispatcherFunc func(ctx context.Context, w *ResponseWriter, q wire.Message, raw []byte)

// Dispatch calls f.
func (f DispatcherFunc) Dispatch(ctx context.Context, w *ResponseWriter, q wire.Message, raw []byte) {
	f(ctx, w, q, raw)
}

// LoopConfig holds the per-listener configuration for [Run]. Zero
// values disable a knob (no cap, no deadline). The Listener and
// Dispatcher fields are required.
type LoopConfig struct {
	// Listener supplies the accepted connections. Run closes it on exit.
	Listener net.Listener

	// LocalAddr is the bound address surfaced through the
	// ResponseWriter to handlers.
	LocalAddr netip.AddrPort

	// Network is the transport label surfaced through
	// ResponseWriter.Network() ("tcp", "dot", ...).
	Network string

	// Dispatcher handles each decoded query.
	Dispatcher Dispatcher

	// PrepareConn, if set, runs once per accepted connection before
	// the length-framed exchange begins. It returns the conn the loop
	// reads/writes from — for DoT this is the *tls.Conn produced by
	// tls.Server; for plain TCP PrepareConn is nil and the raw conn is
	// used. An error aborts the connection silently.
	PrepareConn func(ctx context.Context, raw net.Conn) (net.Conn, error)

	// HandshakeTimeout bounds the time PrepareConn may take. A
	// non-positive value disables the separate deadline. While
	// PrepareConn runs the raw conn deadline is set to time.Now() +
	// HandshakeTimeout; on success the deadline is cleared before the
	// framed exchange begins. Has no effect when PrepareConn is nil.
	HandshakeTimeout time.Duration

	// MaxConnections caps the number of concurrent connections. The
	// accept loop blocks on a counting semaphore once the cap is hit,
	// leaving excess connections queued in the kernel TCP backlog.
	// Non-positive disables the cap.
	MaxConnections int

	// MaxConnsPerSource caps connections per remote IP (Unmap'd so
	// v4-mapped IPv6 shares its v4 bucket). Excess connections are
	// closed immediately. Non-positive disables the cap.
	MaxConnsPerSource int

	// IdleTimeout governs the wait between messages on a persistent
	// connection (RFC 7766 §6.5 for TCP, RFC 7858 §3.4 for DoT). A
	// non-positive value disables the deadline.
	IdleTimeout time.Duration

	// MessageReadTimeout bounds the body read once the 2-byte length
	// prefix is in hand. Without a tighter deadline a peer that drips
	// body bytes just under the idle interval can pin a slot for
	// hours (idle * maxQueriesPerConn). Non-positive disables the
	// per-message deadline (falls back to IdleTimeout).
	MessageReadTimeout time.Duration

	// WriteTimeout caps how long a single response write may take.
	// Without it a slow-read attacker (zero receive window) can pin a
	// server goroutine indefinitely. Non-positive disables.
	WriteTimeout time.Duration

	// MaxLifetime caps wall-clock time a single connection may
	// remain open. Non-positive disables.
	MaxLifetime time.Duration

	// MaxQueriesPerConn caps the total queries served on a single
	// connection. Non-positive disables.
	MaxQueriesPerConn int

	// MaxMessageSize caps the length-prefixed body the loop will
	// read. Non-positive disables (allows up to 65535).
	MaxMessageSize int

	// MaxInflightPerConn caps the number of concurrently-running
	// dispatcher goroutines per connection. Non-positive disables
	// pipelining (dispatchers run serially).
	MaxInflightPerConn int

	// AcceptErrorWrap, if non-empty, is prepended to permanent Accept
	// errors via fmt.Errorf("%s: %w", AcceptErrorWrap, err). The
	// resulting error is returned from Run. Useful so each transport
	// surfaces its own log prefix ("acidns: tcp accept", "dot:
	// accept", ...).
	AcceptErrorWrap string
}

// ResponseWriter writes length-framed responses on the connection
// owned by the loop. Multiple ResponseWriter values may exist
// concurrently for the same connection (pipelined RFC 7766 §6.2.1.1
// responses); a shared mutex serialises the actual writes so two
// concurrent WriteMsg calls cannot interleave length prefixes and
// bodies.
type ResponseWriter struct {
	conn         net.Conn
	remote       netip.AddrPort
	local        netip.AddrPort
	network      string
	writeTimeout time.Duration
	writeMu      *sync.Mutex
}

// RemoteAddr returns the peer's address.
func (w *ResponseWriter) RemoteAddr() netip.AddrPort { return w.remote }

// LocalAddr returns the listener's bound address.
func (w *ResponseWriter) LocalAddr() netip.AddrPort { return w.local }

// Network returns the transport label set on the LoopConfig.
func (w *ResponseWriter) Network() string { return w.network }

// WriteMsg serialises m and writes it as a length-framed message. The
// write is bounded by WriteTimeout when non-zero. Returns an error if
// the marshalled message exceeds the 16-bit length prefix.
func (w *ResponseWriter) WriteMsg(m wire.Message) error {
	buf, err := wire.Pack(m)
	if err != nil {
		return err
	}
	if len(buf) > 0xffff {
		return fmt.Errorf("streamframe: response exceeds 65535 bytes")
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

// Run runs the accept-and-dispatch loop with cfg until ctx is
// cancelled or the listener errors fatally. The listener is closed
// before Run returns. On clean shutdown via ctx cancellation Run
// returns [ErrServerClosed]; transient Accept errors are backed off
// per [netutil.AcceptBackoffInitial]/[netutil.AcceptBackoffCap]; permanent
// errors are wrapped with cfg.AcceptErrorWrap and returned.
//
// Run blocks until every per-connection goroutine has drained.
func Run(ctx context.Context, cfg LoopConfig) error {
	bufSize := cfg.MaxMessageSize
	if bufSize <= 0 {
		bufSize = 65535
	}
	pool := &sync.Pool{New: func() any {
		b := make([]byte, bufSize)
		return &b
	}}

	var sem chan struct{}
	if cfg.MaxConnections > 0 {
		sem = make(chan struct{}, cfg.MaxConnections)
	}
	srcLimiter := netutil.NewSourceLimiter(cfg.MaxConnsPerSource)

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = cfg.Listener.Close()
		case <-stop:
		}
	}()

	var wg sync.WaitGroup
	defer wg.Wait()

	tempBackoff := time.Duration(0)
	for {
		// Slot is acquired BEFORE Accept on purpose: when the cap is
		// reached, the loop blocks here instead of accepting, leaving
		// excess connections queued in the kernel TCP backlog. The
		// well-known alternative — Accept first, then try to acquire
		// and close on miss — gives the off-by-one back (effective
		// cap N vs N-1 when the loop sits in Accept holding one slot)
		// at the cost of completing 3-way handshakes only to RST them
		// and losing kernel-backlog backpressure.
		if sem != nil {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				_ = cfg.Listener.Close()
				return ErrServerClosed
			}
		}
		conn, err := cfg.Listener.Accept()
		if err != nil {
			if sem != nil {
				<-sem
			}
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return ErrServerClosed
			}
			if netutil.IsAcceptTransient(err) {
				if tempBackoff == 0 {
					tempBackoff = netutil.AcceptBackoffInitial
				} else {
					tempBackoff *= 2
					if tempBackoff > netutil.AcceptBackoffCap {
						tempBackoff = netutil.AcceptBackoffCap
					}
				}
				timer := time.NewTimer(tempBackoff)
				select {
				case <-timer.C:
				case <-ctx.Done():
					timer.Stop()
					_ = cfg.Listener.Close()
					return ErrServerClosed
				}
				continue
			}
			if cfg.AcceptErrorWrap != "" {
				return fmt.Errorf("%s: %w", cfg.AcceptErrorWrap, err)
			}
			return err
		}
		tempBackoff = 0
		remote := netutil.RemoteAddrPort(conn)
		if !srcLimiter.Reserve(remote.Addr()) {
			_ = conn.Close()
			if sem != nil {
				<-sem
			}
			continue
		}
		wg.Add(1)
		go func(c net.Conn, src netip.Addr) {
			defer func() {
				srcLimiter.Release(src)
				if sem != nil {
					<-sem
				}
				wg.Done()
			}()
			serveConn(ctx, c, cfg, pool)
		}(conn, remote.Addr())
	}
}

// serveConn drives the per-connection request/response pipeline. It
// invokes cfg.PrepareConn (if any) under the handshake deadline, then
// loops reading length-framed messages and dispatching them to
// cfg.Dispatcher. Responses are written back via [ResponseWriter];
// writes across pipelined dispatchers share a per-connection mutex so
// two responses cannot interleave on the wire.
func serveConn(ctx context.Context, raw net.Conn, cfg LoopConfig, pool *sync.Pool) {
	// LIFO-load-bearing: the conn.Close defer must come BEFORE the
	// connWg.Wait defer below. defers run LIFO so connWg.Wait runs
	// first (dispatcher goroutines drain), THEN conn.Close. Reordering
	// would let pipelined writes hit a closed conn.
	defer func() { _ = raw.Close() }()

	conn := raw
	remote := netutil.RemoteAddrPort(raw)

	if cfg.PrepareConn != nil {
		// Handshake deadline bounds PrepareConn (e.g. TLS). It is
		// kept separate from IdleTimeout so an operator can favour
		// long-lived idle connections without simultaneously widening
		// the peer-stalls-on-ClientHello window. A non-positive value
		// disables the deadline.
		if cfg.HandshakeTimeout > 0 {
			_ = raw.SetDeadline(time.Now().Add(cfg.HandshakeTimeout))
		}
		prepared, err := cfg.PrepareConn(ctx, raw)
		if err != nil {
			return
		}
		_ = raw.SetDeadline(time.Time{})
		conn = prepared
	}

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
	if cfg.MaxLifetime > 0 {
		lifetimeDeadline = time.Now().Add(cfg.MaxLifetime)
	}

	// Writer mutex serialises framed responses across pipelined
	// dispatcher goroutines so two concurrent writes can't interleave
	// length prefixes and bodies.
	var writeMu sync.Mutex

	var perConnSem chan struct{}
	if cfg.MaxInflightPerConn > 0 {
		perConnSem = make(chan struct{}, cfg.MaxInflightPerConn)
	}
	var connWg sync.WaitGroup
	defer connWg.Wait()

	queries := 0
	for {
		if !lifetimeDeadline.IsZero() && time.Now().After(lifetimeDeadline) {
			return
		}
		if cfg.MaxQueriesPerConn > 0 && queries >= cfg.MaxQueriesPerConn {
			return
		}

		readDeadline := time.Time{}
		if cfg.IdleTimeout > 0 {
			readDeadline = time.Now().Add(cfg.IdleTimeout)
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
		if cfg.MaxMessageSize > 0 && n > cfg.MaxMessageSize {
			return
		}

		// Once the length prefix has arrived, the peer is committed
		// to delivering the body promptly. Tighten the read deadline
		// to MessageReadTimeout so a peer cannot drip body bytes at
		// the idle-interval cadence and pin a slot for hours. Still
		// respect the lifetime cap.
		bodyDeadline := time.Time{}
		if cfg.MessageReadTimeout > 0 {
			bodyDeadline = time.Now().Add(cfg.MessageReadTimeout)
		}
		if !lifetimeDeadline.IsZero() && (bodyDeadline.IsZero() || lifetimeDeadline.Before(bodyDeadline)) {
			bodyDeadline = lifetimeDeadline
		}
		if !bodyDeadline.IsZero() {
			_ = conn.SetReadDeadline(bodyDeadline)
		}

		bufp, _ := pool.Get().(*[]byte)
		body := (*bufp)[:n]
		if _, err := io.ReadFull(conn, body); err != nil {
			pool.Put(bufp)
			return
		}
		queries++

		if perConnSem != nil {
			select {
			case perConnSem <- struct{}{}:
			case <-connCtx.Done():
				pool.Put(bufp)
				return
			}
		}
		connWg.Add(1)
		go func(bufp *[]byte, n int) {
			defer func() {
				pool.Put(bufp)
				if perConnSem != nil {
					<-perConnSem
				}
				connWg.Done()
			}()
			body := (*bufp)[:n]
			q, err := wire.Unpack(body)
			if err != nil {
				return
			}
			w := &ResponseWriter{
				conn:         conn,
				remote:       remote,
				local:        cfg.LocalAddr,
				network:      cfg.Network,
				writeTimeout: cfg.WriteTimeout,
				writeMu:      &writeMu,
			}
			cfg.Dispatcher.Dispatch(connCtx, w, q, body)
		}(bufp, n)
	}
}
