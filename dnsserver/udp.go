package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/lestrrat-go/acidns/dnsmsg"
)

// UDPOption configures a UDP server.
type UDPOption interface{ applyUDPServer(*udpConfig) }

type udpOptionFunc func(*udpConfig)

func (f udpOptionFunc) applyUDPServer(c *udpConfig) { f(c) }

type udpConfig struct {
	bufferSize     int
	maxResponseLen int
}

// WithUDPReadBuffer sets the size of the read buffer per packet.
// Defaults to 4096, large enough for an EDNS-extended request.
func WithUDPReadBuffer(n int) UDPOption {
	return udpOptionFunc(func(c *udpConfig) { c.bufferSize = n })
}

// WithUDPMaxResponse sets the absolute upper bound on response size before
// truncation, regardless of any EDNS payload size advertised by the client.
// Defaults to 4096.
func WithUDPMaxResponse(n int) UDPOption {
	return udpOptionFunc(func(c *udpConfig) { c.maxResponseLen = n })
}

type udpServer struct {
	pc      net.PacketConn
	addr    netip.AddrPort
	handler Handler
	cfg     udpConfig
	wg      sync.WaitGroup
}

// ListenUDP binds a UDP socket on addr and returns a Server that dispatches
// each received packet to h. addr.Port may be 0 to ask the kernel for an
// ephemeral port; the actual address is reported by Server.Addr.
func ListenUDP(addr netip.AddrPort, h Handler, opts ...UDPOption) (Server, error) {
	if h == nil {
		return nil, fmt.Errorf("dnsserver: handler is nil")
	}
	cfg := udpConfig{bufferSize: 4096, maxResponseLen: 4096}
	for _, o := range opts {
		o.applyUDPServer(&cfg)
	}

	pc, err := net.ListenPacket("udp", addr.String())
	if err != nil {
		return nil, fmt.Errorf("dnsserver: udp listen %s: %w", addr, err)
	}
	la := pc.LocalAddr().(*net.UDPAddr)
	return &udpServer{
		pc:      pc,
		addr:    netip.AddrPortFrom(la.AddrPort().Addr(), uint16(la.Port)),
		handler: h,
		cfg:     cfg,
	}, nil
}

func (s *udpServer) Addr() netip.AddrPort { return s.addr }

func (s *udpServer) Serve(ctx context.Context) error {
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = s.pc.Close()
		case <-stop:
		}
	}()

	for {
		buf := make([]byte, s.cfg.bufferSize)
		n, src, err := s.pc.ReadFrom(buf)
		if err != nil {
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
			continue
		}
		s.wg.Add(1)
		go func(body []byte, src netip.AddrPort) {
			defer s.wg.Done()
			s.handlePacket(ctx, body, src)
		}(buf[:n], ua.AddrPort())
	}
}

func (s *udpServer) handlePacket(ctx context.Context, body []byte, src netip.AddrPort) {
	q, err := dnsmsg.Unmarshal(body)
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

func (w *udpResponseWriter) WriteMsg(m dnsmsg.Message) error {
	if w.wrote {
		return fmt.Errorf("dnsserver: WriteMsg called twice on UDP response")
	}
	wire, err := dnsmsg.Marshal(m)
	if err != nil {
		return err
	}
	if w.maxLen > 0 && len(wire) > w.maxLen {
		// Truncate per RFC 1035 §4.1.1: keep header + question, drop the
		// rest, set the TC bit.
		var question dnsmsg.Question
		if qs := m.Questions(); len(qs) > 0 {
			question = qs[0]
		}
		b := dnsmsg.NewBuilder().
			ID(m.ID()).
			Flags(m.Flags().WithTruncated(true).WithResponse(true))
		if question != nil {
			b = b.Question(question)
		}
		stripped, err := b.Build()
		if err != nil {
			return err
		}
		wire, err = dnsmsg.Marshal(stripped)
		if err != nil {
			return err
		}
	}
	w.wrote = true
	udst := net.UDPAddrFromAddrPort(w.dst)
	_, err = w.pc.WriteTo(wire, udst)
	return err
}
