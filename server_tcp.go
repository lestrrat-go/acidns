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
	"time"

	"github.com/lestrrat-go/acidns/wire"
)

// TCPListenerOption configures a TCP server.
type TCPListenerOption interface{ applyTCPServer(*tcpListenerConfig) }

type tcpListenerOptionFunc func(*tcpListenerConfig)

func (f tcpListenerOptionFunc) applyTCPServer(c *tcpListenerConfig) { f(c) }

type tcpListenerConfig struct {
	idleTimeout time.Duration
}

// WithTCPIdleTimeout sets how long an idle connection is kept open between
// queries. RFC 7766 §6.5 recommends a few seconds; the default is 10s.
// A non-positive value disables the idle timeout.
func WithTCPIdleTimeout(d time.Duration) TCPListenerOption {
	return tcpListenerOptionFunc(func(c *tcpListenerConfig) { c.idleTimeout = d })
}

type tcpListener struct {
	ln      net.Listener
	addr    netip.AddrPort
	handler Handler
	cfg     tcpListenerConfig
	wg      sync.WaitGroup
}

// ListenTCP binds a TCP socket on addr and returns a Server. Each
// connection is dispatched to a goroutine that loops reading
// length-prefixed queries (RFC 1035 §4.2.2) and writing length-prefixed
// responses (RFC 7766).
func ListenTCP(addr netip.AddrPort, h Handler, opts ...TCPListenerOption) (Server, error) {
	if h == nil {
		return nil, fmt.Errorf("dnsserver: handler is nil")
	}
	cfg := tcpListenerConfig{idleTimeout: 10 * time.Second}
	for _, o := range opts {
		o.applyTCPServer(&cfg)
	}
	ln, err := net.Listen("tcp", addr.String()) //nolint:noctx // listen lifetime is bound to Serve, not the caller's ctx
	if err != nil {
		return nil, fmt.Errorf("dnsserver: tcp listen %s: %w", addr, err)
	}
	la := ln.Addr().(*net.TCPAddr)
	return &tcpListener{
		ln:      ln,
		addr:    netip.AddrPortFrom(la.AddrPort().Addr(), uint16(la.Port)),
		handler: h,
		cfg:     cfg,
	}, nil
}

func (s *tcpListener) Addr() netip.AddrPort { return s.addr }

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

	for {
		conn, err := s.ln.Accept()
		if err != nil {
			s.wg.Wait()
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return ErrServerClosed
			}
			return fmt.Errorf("dnsserver: tcp accept: %w", err)
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			s.serveConn(ctx, c)
		}(conn)
	}
}

func (s *tcpListener) serveConn(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()

	// Cancel pending I/O when the server context is cancelled.
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
		n := binary.BigEndian.Uint16(hdr[:])
		body := make([]byte, n)
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}

		q, err := wire.Unmarshal(body)
		if err != nil {
			return // malformed — close
		}

		w := &tcpResponseWriter{conn: conn, remote: remote, local: s.addr}
		s.handler.ServeDNS(ctx, w, q)
	}
}

type tcpResponseWriter struct {
	conn   net.Conn
	remote netip.AddrPort
	local  netip.AddrPort
}

func (w *tcpResponseWriter) RemoteAddr() netip.AddrPort { return w.remote }
func (w *tcpResponseWriter) LocalAddr() netip.AddrPort  { return w.local }
func (w *tcpResponseWriter) Network() string            { return "tcp" }

func (w *tcpResponseWriter) WriteMsg(m wire.Message) error {
	wire, err := wire.Marshal(m)
	if err != nil {
		return err
	}
	if len(wire) > 0xffff {
		return fmt.Errorf("dnsserver: tcp response exceeds 65535 bytes")
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(wire)))
	if _, err := w.conn.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.conn.Write(wire)
	return err
}
