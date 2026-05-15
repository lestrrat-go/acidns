package acidns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/lestrrat-go/acidns/internal/serverctl"
	"github.com/lestrrat-go/acidns/internal/streamframe"
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

type identTCPListenerIdleTimeout struct{}
type identTCPListenerWriteTimeout struct{}
type identTCPListenerMaxConnections struct{}
type identTCPListenerMaxConnsPerSource struct{}
type identTCPListenerMaxMessageSize struct{}
type identTCPListenerMaxQueriesPerConn struct{}
type identTCPListenerMaxConnLifetime struct{}
type identTCPListenerMessageReadTimeout struct{}
type identTCPListenerMaxInflightPerConn struct{}

// WithTCPListenerIdleTimeout sets how long an idle connection is kept open between
// queries. RFC 7766 §6.5 recommends a few seconds; the default is 10s.
// A non-positive value disables the idle timeout.
func WithTCPListenerIdleTimeout(d time.Duration) TCPListenerOption {
	return tcpListenerOption{option.New(identTCPListenerIdleTimeout{}, d)}
}

// WithTCPListenerWriteTimeout caps how long a single response write may take.
// Without a write deadline a slow-read attacker (TCP receive window 0)
// can pin a server goroutine indefinitely. Default 5s; non-positive
// disables the deadline.
func WithTCPListenerWriteTimeout(d time.Duration) TCPListenerOption {
	return tcpListenerOption{option.New(identTCPListenerWriteTimeout{}, d)}
}

// WithTCPListenerMaxConnections caps the number of concurrent TCP connections.
// Once the cap is reached the accept loop blocks until a slot frees,
// providing natural backpressure via the kernel's TCP listen backlog.
// A non-positive value disables the cap. Defaults to 1024.
func WithTCPListenerMaxConnections(n int) TCPListenerOption {
	return tcpListenerOption{option.New(identTCPListenerMaxConnections{}, n)}
}

// WithTCPListenerMaxConnsPerSource caps the number of concurrent TCP
// connections originating from a single remote IP (canonicalised via
// netip.Addr.Unmap so v4-mapped v6 addresses share a bucket with their
// v4 counterpart). Without this cap a single peer can occupy every slot
// permitted by [WithTCPListenerMaxConnections] and starve all other sources.
// On exceeding the cap the new connection is closed immediately and the
// accept loop continues. A non-positive value disables the per-source
// cap. Defaults to 32 — high enough that a well-behaved client running
// many parallel queries from one host is never affected, low enough
// that a hostile peer cannot starve the listener.
func WithTCPListenerMaxConnsPerSource(n int) TCPListenerOption {
	return tcpListenerOption{option.New(identTCPListenerMaxConnsPerSource{}, n)}
}

// WithTCPListenerMaxMessageSize caps the length-prefixed body the server is
// willing to read from a single TCP query. The 16-bit length prefix
// permits up to 65535 bytes per message; without a tighter ceiling, a
// hostile client can force the server to allocate a 64 KiB buffer per
// connection. Default 16 KiB — wide enough for the largest envelopes
// the bundled AXFR chunker emits while keeping per-connection memory
// bounded. A non-positive value disables the cap (allows up to 65535).
func WithTCPListenerMaxMessageSize(n int) TCPListenerOption {
	return tcpListenerOption{option.New(identTCPListenerMaxMessageSize{}, n)}
}

// WithTCPListenerMaxQueriesPerConn caps the total queries served on a single
// connection before it is closed. Mitigates a peer that holds a slot
// indefinitely at idle-timeout cadence. A non-positive value disables
// the cap. Defaults to 10000 — high enough that a well-behaved RFC
// 7766 client reusing the connection is never affected, low enough
// that a peer cannot pin a slot through arbitrarily many trickled
// queries. Operators MUST tune this for unusual workloads (long-lived
// internal mirrors, AXFR-heavy backplanes).
func WithTCPListenerMaxQueriesPerConn(n int) TCPListenerOption {
	return tcpListenerOption{option.New(identTCPListenerMaxQueriesPerConn{}, n)}
}

// WithTCPListenerMaxConnLifetime caps wall-clock time a single connection may
// remain open. Backstop for misbehaving peers and a way to cycle TLS
// session state on a sane cadence. A non-positive value disables the
// cap. Defaults to 1 hour. Operators MUST tune this for workloads that
// rely on multi-hour streams (e.g. long-lived internal AXFR mirrors).
func WithTCPListenerMaxConnLifetime(d time.Duration) TCPListenerOption {
	return tcpListenerOption{option.New(identTCPListenerMaxConnLifetime{}, d)}
}

// WithTCPListenerMessageReadTimeout caps how long the server will wait for the
// body bytes of a single message after the 2-byte length prefix has
// arrived. The idle timeout ([WithTCPListenerIdleTimeout]) governs the wait
// between messages; once a length prefix is in hand the peer is
// committed to delivering the body promptly, so this deadline is
// tighter. Without this distinction a peer that sends the prefix and
// then drips body bytes just under the idle interval can pin a slot
// for hours (idle * maxQueriesPerConn). Default 5s; non-positive
// disables the per-message deadline (falls back to the idle timeout
// for the body read as well).
func WithTCPListenerMessageReadTimeout(d time.Duration) TCPListenerOption {
	return tcpListenerOption{option.New(identTCPListenerMessageReadTimeout{}, d)}
}

// WithTCPListenerMaxInflightPerConn caps the number of concurrently-running
// handler goroutines per connection. Pipelined responses (RFC 7766
// §6.2.1.1) may be returned out of order; this cap prevents a single
// connection from spawning unbounded handler goroutines if the peer
// pushes queries faster than they complete. Defaults to 32; a
// non-positive value disables pipelining (handlers run serially).
func WithTCPListenerMaxInflightPerConn(n int) TCPListenerOption {
	return tcpListenerOption{option.New(identTCPListenerMaxInflightPerConn{}, n)}
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
		return nil, ErrNilHandler
	}
	if !addr.IsValid() {
		return nil, fmt.Errorf("%w: tcp server bind address", ErrInvalidAddress)
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
		case identTCPListenerIdleTimeout{}:
			cfg.idleTimeout = option.MustGet[time.Duration](o)
		case identTCPListenerWriteTimeout{}:
			cfg.writeTimeout = option.MustGet[time.Duration](o)
		case identTCPListenerMaxConnections{}:
			cfg.maxConnections = option.MustGet[int](o)
		case identTCPListenerMaxConnsPerSource{}:
			cfg.maxConnsPerSource = option.MustGet[int](o)
		case identTCPListenerMaxMessageSize{}:
			cfg.maxMessageSize = option.MustGet[int](o)
		case identTCPListenerMaxQueriesPerConn{}:
			cfg.maxQueriesPerConn = option.MustGet[int](o)
		case identTCPListenerMaxConnLifetime{}:
			cfg.maxConnLifetime = option.MustGet[time.Duration](o)
		case identTCPListenerMessageReadTimeout{}:
			cfg.messageReadTimeout = option.MustGet[time.Duration](o)
		case identTCPListenerMaxInflightPerConn{}:
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

	handler := s.handler
	dispatch := streamframe.DispatcherFunc(func(ctx context.Context, w *streamframe.ResponseWriter, q wire.Message, raw []byte) {
		switch verdict, reply := PreflightRequest(q); verdict {
		case PreflightDrop:
			return
		case PreflightReply:
			_ = w.WriteMsg(reply)
			return
		}
		handler.ServeDNS(contextWithRawRequest(ctx, raw), w, q)
	})

	loopCfg := streamframe.LoopConfig{
		Listener:           ln,
		LocalAddr:          bound,
		Network:            "tcp",
		Dispatcher:         dispatch,
		MaxConnections:     s.cfg.maxConnections,
		MaxConnsPerSource:  s.cfg.maxConnsPerSource,
		IdleTimeout:        s.cfg.idleTimeout,
		MessageReadTimeout: s.cfg.messageReadTimeout,
		WriteTimeout:       s.cfg.writeTimeout,
		MaxLifetime:        s.cfg.maxConnLifetime,
		MaxQueriesPerConn:  s.cfg.maxQueriesPerConn,
		MaxMessageSize:     s.cfg.maxMessageSize,
		MaxInflightPerConn: s.cfg.maxInflightPer,
		AcceptErrorWrap:    "acidns: tcp accept",
	}

	ctrl := &TCPController{Core: serverctl.New(bound)}
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
