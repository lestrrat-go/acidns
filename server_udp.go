package acidns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/lestrrat-go/acidns/internal/netutil"
	"github.com/lestrrat-go/acidns/internal/serverctl"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/option/v3"
)

// UDPListenerOption configures a UDP server.
type UDPListenerOption interface {
	option.Interface
	udpListenerOption()
}

type udpListenerOption struct{ option.Interface }

func (udpListenerOption) udpListenerOption() {}

type udpListenerConfig struct {
	bufferSize     int
	maxResponseLen int
	maxInflight    int
	writeTimeout   time.Duration
	preParseFilter func(netip.AddrPort) bool
}

type identUDPListenerBufferSize struct{}
type identUDPListenerMaxResponse struct{}
type identUDPListenerMaxInflight struct{}
type identUDPListenerWriteTimeout struct{}
type identUDPListenerPreParseFilter struct{}

// WithUDPListenerBufferSize sets the size of the read buffer per
// packet. Defaults to 4096, large enough for an EDNS-extended
// request. The client-side counterpart is [WithUDPClientBufferSize];
// both sides carry the explicit Client/Listener infix so the
// call-site telegraphs which side it configures.
func WithUDPListenerBufferSize(n int) UDPListenerOption {
	return udpListenerOption{option.New(identUDPListenerBufferSize{}, n)}
}

// WithUDPListenerMaxResponse sets the absolute upper bound on response size before
// truncation, regardless of any EDNS payload size advertised by the client.
// Defaults to 1232 per DNS Flag Day 2020 — staying at or below the typical
// IPv6 minimum MTU minus headers avoids IP fragmentation, which is the
// vector for the well-documented amplification and frag-attack classes.
// Raise this only if you understand the trade.
//
// Non-positive values are silently clamped to the default 1232 — a
// caller passing 0 (a zero-valued config field) must not end up with
// truncation disabled, which would expose the listener as an
// amplification primitive serving up to the wire ceiling (65535).
func WithUDPListenerMaxResponse(n int) UDPListenerOption {
	if n <= 0 {
		n = 1232
	}
	return udpListenerOption{option.New(identUDPListenerMaxResponse{}, n)}
}

// WithUDPListenerMaxInflight caps the number of concurrently-running handler
// goroutines. Packets that arrive while the cap is reached are dropped
// silently — the kernel UDP buffer absorbs short bursts and a busy-but-
// healthy server returns to steady state without unbounded goroutine
// growth. A non-positive value disables the cap. Defaults to 4096.
func WithUDPListenerMaxInflight(n int) UDPListenerOption {
	return udpListenerOption{option.New(identUDPListenerMaxInflight{}, n)}
}

// WithUDPListenerPreParseFilter installs a per-datagram source-address gate
// that runs BEFORE wire.Unpack. A return of false drops the
// datagram immediately, skipping every Handler middleware (ACL,
// ratelimit, RRL, cookies, observe). Use this when an operator
// relies on a source-prefix denylist to defend against floods of
// spoofed datagrams whose per-packet parse cost would otherwise pin
// CPU regardless of how strict the post-parse middleware is.
//
// The filter must be safe for concurrent use and should be O(1) —
// it runs on the hot read path. Returning true falls through to
// normal handler dispatch. A nil filter is a no-op.
func WithUDPListenerPreParseFilter(f func(netip.AddrPort) bool) UDPListenerOption {
	return udpListenerOption{option.New(identUDPListenerPreParseFilter{}, f)}
}

// WithUDPListenerWriteTimeout caps how long a single response WriteTo may
// take. UDP writes are normally instant — the kernel send buffer
// fills and the syscall returns — but on a saturated host or a
// pathological socket configuration a write can block. Default 5s;
// non-positive disables the deadline.
//
// The listening socket is shared across all in-flight handler
// goroutines, so [net.PacketConn.SetWriteDeadline] would race across
// writers. The implementation serialises Deadline+WriteTo through a
// per-listener mutex so each writer sees its own deadline. The hold
// time is bounded by the deadline itself.
func WithUDPListenerWriteTimeout(d time.Duration) UDPListenerOption {
	return udpListenerOption{option.New(identUDPListenerWriteTimeout{}, d)}
}

// UDPServer is an immutable configuration holder for a UDP DNS server.
// It carries the listen address, the Handler, and applied options;
// it does NOT carry runtime state. Call [UDPServer.Run] to spawn an
// independent server instance — the same UDPServer may be Run any
// number of times to spawn parallel instances, useful for testing
// or multi-socket deployments. The running instance is reachable
// only through the returned [*UDPController].
type UDPServer struct {
	addr    netip.AddrPort
	handler Handler
	cfg     udpListenerConfig
}

// NewUDPServer validates the configuration. It does NOT bind a socket;
// pass the result to Run when you're ready to start serving. The
// returned value is safe to share across goroutines and may be Run
// multiple times to spawn multiple independent server instances.
func NewUDPServer(addr netip.AddrPort, h Handler, opts ...UDPListenerOption) (*UDPServer, error) {
	if h == nil {
		return nil, ErrNilHandler
	}
	if !addr.IsValid() {
		return nil, fmt.Errorf("%w: udp server bind address", ErrInvalidAddress)
	}
	cfg := udpListenerConfig{
		bufferSize:     4096,
		maxResponseLen: 1232,
		maxInflight:    4096,
		writeTimeout:   5 * time.Second,
	}
	for _, o := range opts {
		switch o.Ident() {
		case identUDPListenerBufferSize{}:
			cfg.bufferSize = option.MustGet[int](o)
		case identUDPListenerMaxResponse{}:
			n := option.MustGet[int](o)
			if n > 0 {
				cfg.maxResponseLen = n
			}
			// Non-positive: keep the default to avoid an open
			// amplification surface.
		case identUDPListenerMaxInflight{}:
			cfg.maxInflight = option.MustGet[int](o)
		case identUDPListenerWriteTimeout{}:
			cfg.writeTimeout = option.MustGet[time.Duration](o)
		case identUDPListenerPreParseFilter{}:
			cfg.preParseFilter = option.MustGet[func(netip.AddrPort) bool](o)
		}
	}
	return &UDPServer{addr: addr, handler: h, cfg: cfg}, nil
}

// Run binds a fresh UDP socket and spawns a new dispatch goroutine.
// Each call constructs an independent server instance; the receiver
// holds only configuration and is unchanged by Run. The returned
// UDPController is the sole handle to the new instance: it exposes
// the bound address (which may differ from the requested address
// when port=0) and a Done channel that closes once the goroutine
// has exited cleanly. Cancel ctx to stop the instance; the
// goroutine drains in-flight handlers before closing.
func (s *UDPServer) Run(ctx context.Context) (*UDPController, error) {
	pc, err := net.ListenPacket("udp", s.addr.String()) //nolint:noctx // socket lifetime is bound to Run's ctx, not the bind call
	if err != nil {
		return nil, fmt.Errorf("acidns: udp listen %s: %w", s.addr, err)
	}
	la, ok := pc.LocalAddr().(*net.UDPAddr)
	if !ok {
		_ = pc.Close()
		return nil, fmt.Errorf("acidns: udp listen %s: unexpected addr type %T", s.addr, pc.LocalAddr())
	}
	bound := netip.AddrPortFrom(la.AddrPort().Addr(), uint16(la.Port))

	ctrl := &UDPController{Core: serverctl.New(bound)}
	loop := &udpLoop{
		pc:      pc,
		addr:    bound,
		handler: s.handler,
		cfg:     s.cfg,
		ctrl:    ctrl,
	}
	if s.cfg.maxInflight > 0 {
		loop.sem = make(chan struct{}, s.cfg.maxInflight)
	}
	loop.bufPool.New = func() any {
		b := make([]byte, s.cfg.bufferSize)
		return &b
	}

	go func() {
		defer ctrl.CloseDone()
		err := loop.run(ctx)
		if err != nil && !errors.Is(err, ErrServerClosed) {
			ctrl.SetErr(err)
		}
	}()

	return ctrl, nil
}

// udpLoop owns the runtime state of a serving UDP listener. All
// fields are written from the dispatch goroutine; nothing external
// holds a pointer to udpLoop, so no synchronisation is required
// beyond what handler dispatch already arranges.
//
// writeMu serialises (SetWriteDeadline, WriteTo) on the shared
// [net.PacketConn] across handler goroutines. Without it concurrent
// writers can clobber each other's deadlines, producing spurious
// deadline-exceeded errors that look like network failures.
type udpLoop struct {
	pc      net.PacketConn
	addr    netip.AddrPort
	handler Handler
	cfg     udpListenerConfig
	sem     chan struct{}
	bufPool sync.Pool
	wg      sync.WaitGroup
	writeMu sync.Mutex
	ctrl    *UDPController
}

func (l *udpLoop) run(ctx context.Context) error {
	// Cancel the read loop on ctx done by closing the socket; the
	// kernel surfaces a net.ErrClosed which the read path treats as
	// the shutdown signal.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = l.pc.Close()
		case <-stop:
		}
	}()

	defer l.wg.Wait() // drain in-flight handlers before signalling Done

	const readBackoffStart = 5 * time.Millisecond
	const readBackoffCap = time.Second
	tempBackoff := time.Duration(0)

	for {
		bufp, _ := l.bufPool.Get().(*[]byte) // pool's New always returns *[]byte
		buf := *bufp
		n, src, err := l.pc.ReadFrom(buf)
		if err != nil {
			l.bufPool.Put(bufp)
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return ErrServerClosed
			}
			// Transient kernel-resource errors (ENOBUFS / ENOMEM /
			// EAGAIN, etc.) on ReadFrom under load must NOT terminate
			// the listener. Mirror the TCP accept-loop's exponential
			// backoff and continue.
			if netutil.IsAcceptTransient(err) {
				if tempBackoff == 0 {
					tempBackoff = readBackoffStart
				} else {
					tempBackoff *= 2
					if tempBackoff > readBackoffCap {
						tempBackoff = readBackoffCap
					}
				}
				timer := time.NewTimer(tempBackoff)
				select {
				case <-timer.C:
				case <-ctx.Done():
					timer.Stop()
					return ErrServerClosed
				}
				continue
			}
			return fmt.Errorf("acidns: udp read: %w", err)
		}
		tempBackoff = 0

		ua, ok := src.(*net.UDPAddr)
		if !ok {
			l.bufPool.Put(bufp)
			continue
		}
		if l.cfg.preParseFilter != nil && !l.cfg.preParseFilter(ua.AddrPort()) {
			l.bufPool.Put(bufp)
			if l.ctrl != nil {
				l.ctrl.preFilterDrops.Add(1)
			}
			continue
		}
		if l.sem != nil {
			select {
			case l.sem <- struct{}{}:
			default:
				l.bufPool.Put(bufp) // at concurrency cap — drop & recycle
				if l.ctrl != nil {
					l.ctrl.inflightDrops.Add(1)
				}
				continue
			}
		}
		l.wg.Add(1)
		go func(bufp *[]byte, n int, src netip.AddrPort) {
			defer func() {
				l.bufPool.Put(bufp)
				if l.sem != nil {
					<-l.sem
				}
				l.wg.Done()
			}()
			l.handlePacket(ctx, (*bufp)[:n], src)
		}(bufp, n, ua.AddrPort())
	}
}

func (l *udpLoop) handlePacket(ctx context.Context, body []byte, src netip.AddrPort) {
	q, err := wire.Unpack(body)
	if err != nil {
		if l.ctrl != nil {
			l.ctrl.parseDrops.Add(1)
		}
		return // malformed → drop silently
	}

	maxResp := 512
	if e, ok := q.EDNS(); ok {
		if size := int(e.UDPSize()); size > maxResp {
			maxResp = size
		}
	}
	if maxResp > l.cfg.maxResponseLen {
		maxResp = l.cfg.maxResponseLen
	}

	ctx = contextWithRawRequest(ctx, body)
	w := &udpResponseWriter{
		pc:           l.pc,
		writeMu:      &l.writeMu,
		dst:          src,
		local:        l.addr,
		maxLen:       maxResp,
		writeTimeout: l.cfg.writeTimeout,
	}

	switch verdict, reply := PreflightRequest(q); verdict {
	case PreflightDrop:
		l.ctrl.preflightDrops.Add(1)
		return
	case PreflightReply:
		_ = w.WriteMsg(reply)
		return
	}

	l.handler.ServeDNS(ctx, w, q)
}

type udpResponseWriter struct {
	pc           net.PacketConn
	writeMu      *sync.Mutex
	dst          netip.AddrPort
	local        netip.AddrPort
	maxLen       int
	writeTimeout time.Duration
	wrote        bool
}

func (w *udpResponseWriter) RemoteAddr() netip.AddrPort { return w.dst }
func (w *udpResponseWriter) LocalAddr() netip.AddrPort  { return w.local }
func (w *udpResponseWriter) Network() string            { return "udp" }

func (w *udpResponseWriter) WriteMsg(m wire.Message) error {
	if w.wrote {
		return fmt.Errorf("acidns: WriteMsg called twice on UDP response")
	}
	buf, err := wire.Pack(m)
	if err != nil {
		return err
	}
	if w.maxLen > 0 && len(buf) > w.maxLen {
		// Truncate per RFC 1035 §4.1.1: set the TC bit and keep the
		// header + question. Per RFC 6891 §6.1.1 we must echo the OPT
		// pseudo-RR if the original response carried one, otherwise the
		// client cannot tell EDNS-aware servers from broken ones and may
		// permanently downgrade. Opcode and RCODE are preserved so the
		// client can still classify the response. AA and AD describe
		// statements about the answer data — they do not hold over a
		// stripped body, so clear them.
		b := wire.NewMessageBuilder().
			ID(m.ID()).
			Flags(m.Flags().
				WithTruncated(true).
				WithResponse(true).
				WithAuthoritative(false).
				WithAuthenticData(false))
		if qs := m.Questions(); len(qs) > 0 {
			b = b.Question(qs[0])
		}
		if e, ok := m.EDNS(); ok {
			b = b.EDNS(e)
		}
		stripped, err := b.Build()
		if err != nil {
			return err
		}
		buf, err = wire.Pack(stripped)
		if err != nil {
			return err
		}
	}
	w.wrote = true
	udst := net.UDPAddrFromAddrPort(w.dst)
	// Serialise (SetWriteDeadline, WriteTo) on the shared PacketConn:
	// concurrent writers would otherwise race on the per-conn
	// deadline.
	if w.writeMu != nil {
		w.writeMu.Lock()
		defer w.writeMu.Unlock()
	}
	if w.writeTimeout > 0 {
		_ = w.pc.SetWriteDeadline(time.Now().Add(w.writeTimeout))
	}
	_, err = w.pc.WriteTo(buf, udst)
	return err
}
