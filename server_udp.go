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

type udpListener struct {
	pc        net.PacketConn
	addr      netip.AddrPort
	handler   Handler
	cfg       udpListenerConfig
	sem       chan struct{}
	bufPool   sync.Pool
	wg        sync.WaitGroup
	closeOnce sync.Once

	// handlerCtx is the parent context for every dispatched handler.
	// Both Shutdown and Serve-context cancellation cancel it so
	// in-flight handlers observe shutdown rather than running until
	// their own work happens to finish.
	handlerCtx    context.Context
	handlerCancel context.CancelFunc
}

// ListenUDP binds a UDP socket on addr and returns a Server that dispatches
// each received packet to h. addr.Port may be 0 to ask the kernel for an
// ephemeral port; the actual address is reported by Server.Addr.
func ListenUDP(addr netip.AddrPort, h Handler, opts ...UDPListenerOption) (Server, error) {
	if h == nil {
		return nil, fmt.Errorf("dnsserver: handler is nil")
	}
	cfg := udpListenerConfig{bufferSize: 4096, maxResponseLen: 4096, maxInflight: 4096}
	for _, o := range opts {
		o.applyUDPServer(&cfg)
	}

	pc, err := net.ListenPacket("udp", addr.String()) //nolint:noctx // listen lifetime is bound to Serve, not the caller's ctx
	if err != nil {
		return nil, fmt.Errorf("dnsserver: udp listen %s: %w", addr, err)
	}
	la, ok := pc.LocalAddr().(*net.UDPAddr)
	if !ok {
		_ = pc.Close()
		return nil, fmt.Errorf("dnsserver: udp listen %s: unexpected addr type %T", addr, pc.LocalAddr())
	}
	hctx, hcancel := context.WithCancel(context.Background())
	l := &udpListener{
		pc:            pc,
		addr:          netip.AddrPortFrom(la.AddrPort().Addr(), uint16(la.Port)),
		handler:       h,
		cfg:           cfg,
		handlerCtx:    hctx,
		handlerCancel: hcancel,
	}
	if cfg.maxInflight > 0 {
		l.sem = make(chan struct{}, cfg.maxInflight)
	}
	l.bufPool.New = func() any {
		b := make([]byte, cfg.bufferSize)
		return &b
	}
	return l, nil
}

func (s *udpListener) Addr() netip.AddrPort { return s.addr }

// Shutdown closes the listening socket so Serve returns ErrServerClosed,
// cancels the handler context so in-flight handlers observe shutdown,
// then waits for in-flight handler goroutines to finish. If ctx expires
// before that happens, the context error is returned and the dangling
// handlers continue running until they exit on their own.
func (s *udpListener) Shutdown(ctx context.Context) error {
	s.closeOnce.Do(func() {
		s.handlerCancel()
		_ = s.pc.Close()
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

func (s *udpListener) Serve(ctx context.Context) error {
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			s.handlerCancel()
			_ = s.pc.Close()
		case <-s.handlerCtx.Done():
			_ = s.pc.Close()
		case <-stop:
		}
	}()

	for {
		bufp, _ := s.bufPool.Get().(*[]byte) // pool's New always returns *[]byte
		buf := *bufp
		n, src, err := s.pc.ReadFrom(buf)
		if err != nil {
			s.bufPool.Put(bufp)
			s.wg.Wait()
			if ctx.Err() != nil {
				return ErrServerClosed
			}
			if errors.Is(err, net.ErrClosed) {
				return ErrServerClosed
			}
			return fmt.Errorf("dnsserver: udp read: %w", err)
		}

		ua, ok := src.(*net.UDPAddr)
		if !ok {
			s.bufPool.Put(bufp)
			continue
		}
		if s.sem != nil {
			select {
			case s.sem <- struct{}{}:
			default:
				s.bufPool.Put(bufp) // at concurrency cap — drop & recycle
				continue
			}
		}
		s.wg.Add(1)
		go func(bufp *[]byte, n int, src netip.AddrPort) {
			defer func() {
				s.bufPool.Put(bufp)
				if s.sem != nil {
					<-s.sem
				}
				s.wg.Done()
			}()
			s.handlePacket(s.handlerCtx, (*bufp)[:n], src)
		}(bufp, n, ua.AddrPort())
	}
}

func (s *udpListener) handlePacket(ctx context.Context, body []byte, src netip.AddrPort) {
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
	if maxResp > s.cfg.maxResponseLen {
		maxResp = s.cfg.maxResponseLen
	}

	ctx = contextWithRawRequest(ctx, body)
	w := &udpResponseWriter{
		pc:     s.pc,
		dst:    src,
		local:  s.addr,
		maxLen: maxResp,
	}
	s.handler.ServeDNS(ctx, w, q)
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
