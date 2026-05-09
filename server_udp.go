package acidns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/lestrrat-go/acidns/internal/serverctl"
	"github.com/lestrrat-go/acidns/wire"
)

// UDPListenerOption configures a UDP server.
type UDPListenerOption interface{ applyUDPServer(*udpListenerConfig) }

type udpListenerOptionFunc func(*udpListenerConfig)

func (f udpListenerOptionFunc) applyUDPServer(c *udpListenerConfig) { f(c) }

type udpListenerConfig struct {
	bufferSize     int
	maxResponseLen int
	maxInflight    int
	writeTimeout   time.Duration
}

// WithUDPListenerBufferSize sets the size of the read buffer per
// packet. Defaults to 4096, large enough for an EDNS-extended
// request. The client-side counterpart is [WithUDPReadBufferSize];
// the names diverge because Go disallows two top-level functions
// with the same identifier in the same package, so the listener
// form takes the explicit Listener prefix.
func WithUDPListenerBufferSize(n int) UDPListenerOption {
	return udpListenerOptionFunc(func(c *udpListenerConfig) { c.bufferSize = n })
}

// WithUDPMaxResponse sets the absolute upper bound on response size before
// truncation, regardless of any EDNS payload size advertised by the client.
// Defaults to 1232 per DNS Flag Day 2020 — staying at or below the typical
// IPv6 minimum MTU minus headers avoids IP fragmentation, which is the
// vector for the well-documented amplification and frag-attack classes.
// Raise this only if you understand the trade.
func WithUDPMaxResponse(n int) UDPListenerOption {
	return udpListenerOptionFunc(func(c *udpListenerConfig) { c.maxResponseLen = n })
}

// WithUDPMaxInflight caps the number of concurrently-running handler
// goroutines. Packets that arrive while the cap is reached are dropped
// silently — the kernel UDP buffer absorbs short bursts and a busy-but-
// healthy server returns to steady state without unbounded goroutine
// growth. A non-positive value disables the cap. Defaults to 4096.
func WithUDPMaxInflight(n int) UDPListenerOption {
	return udpListenerOptionFunc(func(c *udpListenerConfig) { c.maxInflight = n })
}

// WithUDPWriteTimeout caps how long a single response WriteTo may
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
func WithUDPWriteTimeout(d time.Duration) UDPListenerOption {
	return udpListenerOptionFunc(func(c *udpListenerConfig) { c.writeTimeout = d })
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
		return nil, fmt.Errorf("acidns: handler is nil")
	}
	if !addr.IsValid() {
		return nil, fmt.Errorf("acidns: invalid bind address")
	}
	cfg := udpListenerConfig{
		bufferSize:     4096,
		maxResponseLen: 1232,
		maxInflight:    4096,
		writeTimeout:   5 * time.Second,
	}
	for _, o := range opts {
		o.applyUDPServer(&cfg)
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
			if isAcceptTransient(err) {
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
		if l.sem != nil {
			select {
			case l.sem <- struct{}{}:
			default:
				l.bufPool.Put(bufp) // at concurrency cap — drop & recycle
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
	q, err := wire.Unmarshal(body)
	if err != nil {
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
	buf, err := wire.Marshal(m)
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
		buf, err = wire.Marshal(stripped)
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
