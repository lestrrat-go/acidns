package acidns_test

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// keepAliveServer counts connections accepted, lets the test inspect what
// the client sent, and answers each query with a NoError reply that
// echoes back an edns-tcp-keepalive option carrying the configured idle.
type keepAliveServer struct {
	conns        atomic.Int64
	queries      atomic.Int64
	advertise    time.Duration
	gotKeepalive atomic.Bool
}

func startKeepAliveServer(t *testing.T, srv *keepAliveServer) (netip.AddrPort, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().(*net.TCPAddr).AddrPort()

	stop := make(chan struct{})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			srv.conns.Add(1)
			go srv.handle(c, stop)
		}
	}()
	return addr, func() {
		close(stop)
		_ = ln.Close()
	}
}

func (s *keepAliveServer) handle(c net.Conn, stop <-chan struct{}) {
	defer func() { _ = c.Close() }()
	for {
		select {
		case <-stop:
			return
		default:
		}
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		var hdr [2]byte
		if _, err := readFull(c, hdr[:]); err != nil {
			return
		}
		n := int(hdr[0])<<8 | int(hdr[1])
		body := make([]byte, n)
		if _, err := readFull(c, body); err != nil {
			return
		}
		s.queries.Add(1)

		q, err := wire.Unmarshal(body)
		if err != nil {
			return
		}
		if e, ok := q.EDNS(); ok {
			for _, o := range e.Options() {
				if o.Code() == wire.EDNSOptionTCPKeepalive {
					s.gotKeepalive.Store(true)
				}
			}
		}

		eb := wire.NewEDNSBuilder().UDPSize(1232)
		if s.advertise >= 0 {
			// Always emit a 2-byte payload — the helper's empty-payload
			// path is the client-opt-in form, not a server-side advertise.
			units := uint16(s.advertise / (100 * time.Millisecond))
			opt, _ := wire.NewEDNSOption(wire.EDNSOptionTCPKeepalive,
				[]byte{byte(units >> 8), byte(units)})
			eb = eb.Option(opt)
		}
		respMsg, err := wire.NewBuilder().
			ID(q.ID()).
			Response(true).
			RecursionAvailable(true).
			Question(q.Questions()[0]).
			EDNS(eb.Build()).
			Build()
		if err != nil {
			return
		}
		raw, err := wire.Marshal(respMsg)
		if err != nil {
			return
		}
		var lh [2]byte
		lh[0] = byte(len(raw) >> 8)
		lh[1] = byte(len(raw))
		if _, err := c.Write(lh[:]); err != nil {
			return
		}
		if _, err := c.Write(raw); err != nil {
			return
		}
	}
}

func readFull(c net.Conn, b []byte) (int, error) {
	got := 0
	for got < len(b) {
		n, err := c.Read(b[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}

func newQuery(t *testing.T, name string) wire.Message {
	t.Helper()
	q, err := wire.NewBuilder().
		ID(0x4242).
		RecursionDesired(true).
		Question(wire.NewQuestion(wire.MustParseName(name), rrtype.A)).
		Build()
	require.NoError(t, err)
	return q
}

func TestKeepAliveReusesConnection(t *testing.T) {
	t.Parallel()
	srv := &keepAliveServer{advertise: 10 * time.Second}
	addr, stop := startKeepAliveServer(t, srv)
	defer stop()

	ex, err := acidns.NewTCPKeepAliveExchanger(addr)
	require.NoError(t, err)

	for i := 0; i < 3; i++ {
		_, err := ex.Exchange(t.Context(), newQuery(t, "example.com"))
		require.NoError(t, err)
	}
	require.True(t, srv.gotKeepalive.Load(), "client must inject edns-tcp-keepalive")
	require.Equal(t, int64(1), srv.conns.Load(), "expected single persistent connection")
	require.Equal(t, int64(3), srv.queries.Load())
}

func TestKeepAliveServerSignalsClose(t *testing.T) {
	t.Parallel()
	// 0 means "close after this exchange" per RFC 7828 §3.3.2.
	srv := &keepAliveServer{advertise: 0}
	addr, stop := startKeepAliveServer(t, srv)
	defer stop()

	ex, err := acidns.NewTCPKeepAliveExchanger(addr)
	require.NoError(t, err)

	for i := 0; i < 3; i++ {
		_, err := ex.Exchange(t.Context(), newQuery(t, "example.com"))
		require.NoError(t, err)
	}
	require.Equal(t, int64(3), srv.conns.Load(), "each exchange should redial")
}

func TestKeepAliveLocalIdleFallback(t *testing.T) {
	t.Parallel()
	// Server sends no keepalive option at all; the client falls back to
	// its local idle setting to decide when to close the cached conn.
	srv := &keepAliveServer{advertise: -1}
	addr, stop := startKeepAliveServer(t, srv)
	defer stop()

	ex, err := acidns.NewTCPKeepAliveExchanger(addr,
		acidns.WithTCPKeepAliveIdle(50*time.Millisecond))
	require.NoError(t, err)

	_, err = ex.Exchange(t.Context(), newQuery(t, "example.com"))
	require.NoError(t, err)
	// Wait past the idle window.
	time.Sleep(120 * time.Millisecond)
	_, err = ex.Exchange(t.Context(), newQuery(t, "example.com"))
	require.NoError(t, err)
	require.GreaterOrEqual(t, srv.conns.Load(), int64(2))
}

func TestKeepAliveRespectsCancel(t *testing.T) {
	t.Parallel()
	srv := &keepAliveServer{advertise: 5 * time.Second}
	addr, stop := startKeepAliveServer(t, srv)
	defer stop()

	ex, err := acidns.NewTCPKeepAliveExchanger(addr)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = ex.Exchange(ctx, newQuery(t, "example.com"))
	require.Error(t, err)
}
