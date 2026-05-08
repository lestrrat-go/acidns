package acidns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

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
}

// WithUDPReadBuffer sets the size of the read buffer per packet.
// Defaults to 4096, large enough for an EDNS-extended request.
func WithUDPReadBuffer(n int) UDPListenerOption {
	return udpListenerOptionFunc(func(c *udpListenerConfig) { c.bufferSize = n })
}

// WithUDPMaxResponse sets the absolute upper bound on response size before
// truncation, regardless of any EDNS payload size advertised by the client.
// Defaults to 4096.
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

// UDPServer is an immutable configuration holder for a UDP DNS server.
// It carries the listen address, the Handler, and applied options;
// it does NOT carry runtime state. Call [UDPServer.Run] to spawn an
// independent server instance — the same UDPServer may be Run any
// number of times to spawn parallel instances, useful for testing
// or multi-socket deployments. The running instance is reachable
// only through the returned [*Controller].
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
		return nil, fmt.Errorf("dnsserver: handler is nil")
	}
	cfg := udpListenerConfig{bufferSize: 4096, maxResponseLen: 4096, maxInflight: 4096}
	for _, o := range opts {
		o.applyUDPServer(&cfg)
	}
	return &UDPServer{addr: addr, handler: h, cfg: cfg}, nil
}

// Run binds a fresh UDP socket and spawns a new dispatch goroutine.
// Each call constructs an independent server instance; the receiver
// holds only configuration and is unchanged by Run. The returned
// Controller is the sole handle to the new instance: it exposes the
// bound address (which may differ from the requested address when
// port=0) and a Done channel that closes once the goroutine has
// exited cleanly. Cancel ctx to stop the instance; the goroutine
// drains in-flight handlers before closing.
func (s *UDPServer) Run(ctx context.Context) (*Controller, error) {
	pc, err := net.ListenPacket("udp", s.addr.String()) //nolint:noctx // socket lifetime is bound to Run's ctx, not the bind call
	if err != nil {
		return nil, fmt.Errorf("dnsserver: udp listen %s: %w", s.addr, err)
	}
	la, ok := pc.LocalAddr().(*net.UDPAddr)
	if !ok {
		_ = pc.Close()
		return nil, fmt.Errorf("dnsserver: udp listen %s: unexpected addr type %T", s.addr, pc.LocalAddr())
	}
	bound := netip.AddrPortFrom(la.AddrPort().Addr(), uint16(la.Port))

	ctrl := newController(bound)
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
		defer close(ctrl.done)
		err := loop.run(ctx)
		if err != nil && !errors.Is(err, ErrServerClosed) {
			ctrl.setErr(err)
		}
	}()

	return ctrl, nil
}

// udpLoop owns the runtime state of a serving UDP listener. All
// fields are written from the dispatch goroutine; nothing external
// holds a pointer to udpLoop, so no synchronisation is required
// beyond what handler dispatch already arranges.
type udpLoop struct {
	pc      net.PacketConn
	addr    netip.AddrPort
	handler Handler
	cfg     udpListenerConfig
	sem     chan struct{}
	bufPool sync.Pool
	wg      sync.WaitGroup
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

	for {
		bufp, _ := l.bufPool.Get().(*[]byte) // pool's New always returns *[]byte
		buf := *bufp
		n, src, err := l.pc.ReadFrom(buf)
		if err != nil {
			l.bufPool.Put(bufp)
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return ErrServerClosed
			}
			return fmt.Errorf("dnsserver: udp read: %w", err)
		}

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
	if e, ok := q.EDNS(); ok && e != nil {
		if size := int(e.UDPSize()); size > maxResp {
			maxResp = size
		}
	}
	if maxResp > l.cfg.maxResponseLen {
		maxResp = l.cfg.maxResponseLen
	}

	ctx = contextWithRawRequest(ctx, body)
	w := &udpResponseWriter{
		pc:     l.pc,
		dst:    src,
		local:  l.addr,
		maxLen: maxResp,
	}
	l.handler.ServeDNS(ctx, w, q)
}

type udpResponseWriter struct {
	pc     net.PacketConn
	dst    netip.AddrPort
	local  netip.AddrPort
	maxLen int
	wrote  bool
}

func (w *udpResponseWriter) RemoteAddr() netip.AddrPort { return w.dst }
func (w *udpResponseWriter) LocalAddr() netip.AddrPort  { return w.local }
func (w *udpResponseWriter) Network() string            { return "udp" }

func (w *udpResponseWriter) WriteMsg(m wire.Message) error {
	if w.wrote {
		return fmt.Errorf("dnsserver: WriteMsg called twice on UDP response")
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
		// client can still classify the response.
		var question wire.Question
		if qs := m.Questions(); len(qs) > 0 {
			question = qs[0]
		}
		b := wire.NewBuilder().
			ID(m.ID()).
			Flags(m.Flags().WithTruncated(true).WithResponse(true))
		if question != nil {
			b = b.Question(question)
		}
		if e, ok := m.EDNS(); ok && e != nil {
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
	_, err = w.pc.WriteTo(buf, udst)
	return err
}
