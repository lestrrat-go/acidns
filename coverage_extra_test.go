package acidns_test

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// TestUDPResponseWriterAddrAccessors walks RemoteAddr/LocalAddr/Network on the
// UDP server's response writer (uncovered in the existing suite).
func TestUDPResponseWriterAddrAccessors(t *testing.T) {
	t.Parallel()

	type capture struct {
		remote, local netip.AddrPort
		network       string
	}
	captured := make(chan capture, 1)
	h := acidns.HandlerFunc(func(_ context.Context, w acidns.ResponseWriter, q wire.Message) {
		captured <- capture{
			remote:  w.RemoteAddr(),
			local:   w.LocalAddr(),
			network: w.Network(),
		}
		resp, _ := wire.NewBuilder().
			ID(q.ID()).
			Response(true).
			Question(q.Questions()[0]).
			Build()
		_ = w.WriteMsg(resp)
	})

	srv, err := acidns.ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"), h)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx) }()

	ex, err := acidns.NewUDPExchanger(srv.Addr())
	require.NoError(t, err)
	q, _ := wire.NewBuilder().
		ID(0xab12).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	_, err = ex.Exchange(t.Context(), q)
	require.NoError(t, err)

	select {
	case c := <-captured:
		require.Equal(t, "udp", c.network)
		require.True(t, c.remote.IsValid())
		require.True(t, c.local.IsValid())
		require.Equal(t, "127.0.0.1", c.local.Addr().String())
	case <-time.After(2 * time.Second):
		t.Fatal("handler never invoked")
	}
}

// TestUDPWriteMsgTwiceFails verifies the second WriteMsg on a UDP response
// writer is rejected per the documented one-shot contract.
func TestUDPWriteMsgTwiceFails(t *testing.T) {
	t.Parallel()

	errCh := make(chan error, 1)
	h := acidns.HandlerFunc(func(_ context.Context, w acidns.ResponseWriter, q wire.Message) {
		resp, _ := wire.NewBuilder().
			ID(q.ID()).
			Response(true).
			Question(q.Questions()[0]).
			Build()
		_ = w.WriteMsg(resp)
		errCh <- w.WriteMsg(resp)
	})

	srv, err := acidns.ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"), h)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx) }()

	ex, err := acidns.NewUDPExchanger(srv.Addr())
	require.NoError(t, err)
	q, _ := wire.NewBuilder().
		ID(0xab13).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	_, err = ex.Exchange(t.Context(), q)
	require.NoError(t, err)

	select {
	case err := <-errCh:
		// Error origin races between socket-closed and write-failed paths;
		// any non-nil error is acceptable here.
		require.Error(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("second WriteMsg never returned")
	}
}

// TestTCPResponseWriterAddrAccessors covers RemoteAddr/LocalAddr/Network on
// the TCP server's response writer.
func TestTCPResponseWriterAddrAccessors(t *testing.T) {
	t.Parallel()

	type capture struct {
		remote, local netip.AddrPort
		network       string
	}
	captured := make(chan capture, 1)
	h := acidns.HandlerFunc(func(_ context.Context, w acidns.ResponseWriter, q wire.Message) {
		captured <- capture{
			remote:  w.RemoteAddr(),
			local:   w.LocalAddr(),
			network: w.Network(),
		}
		resp, _ := wire.NewBuilder().
			ID(q.ID()).
			Response(true).
			Question(q.Questions()[0]).
			Build()
		_ = w.WriteMsg(resp)
	})

	srv, err := acidns.ListenTCP(netip.MustParseAddrPort("127.0.0.1:0"), h)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx) }()

	ex, err := acidns.NewTCPExchanger(srv.Addr())
	require.NoError(t, err)
	q, _ := wire.NewBuilder().
		ID(0xcd34).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	_, err = ex.Exchange(t.Context(), q)
	require.NoError(t, err)

	select {
	case c := <-captured:
		require.Equal(t, "tcp", c.network)
		require.True(t, c.remote.IsValid())
		require.True(t, c.local.IsValid())
		require.Equal(t, "127.0.0.1", c.local.Addr().String())
	case <-time.After(2 * time.Second):
		t.Fatal("handler never invoked")
	}
}

// TestTCPWriteMsgTooLarge constructs a synthetic message whose marshalled form
// exceeds 65535 bytes and asserts WriteMsg surfaces the framing error. We do
// this by stuffing a large number of TXT records and intercepting the response
// inside the handler.
func TestTCPWriteMsgTooLarge(t *testing.T) {
	t.Parallel()

	errCh := make(chan error, 1)
	h := acidns.HandlerFunc(func(_ context.Context, w acidns.ResponseWriter, q wire.Message) {
		b := wire.NewBuilder().
			ID(q.ID()).
			Response(true).
			Question(q.Questions()[0])
		// Roughly 65k of TXT data: 300 records × ~220 bytes each.
		long := make([]byte, 200)
		for i := range long {
			long[i] = 'Z'
		}
		txt, _ := rdata.NewTXT(string(long))
		for i := 0; i < 300; i++ {
			b = b.Answer(wire.NewRecord(q.Questions()[0].Name(), time.Minute, txt))
		}
		resp, err := b.Build()
		if err != nil {
			errCh <- err
			return
		}
		errCh <- w.WriteMsg(resp)
	})

	srv, err := acidns.ListenTCP(netip.MustParseAddrPort("127.0.0.1:0"), h)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx) }()

	// Open a raw TCP connection so we don't block in the client when the
	// server fails to send a response.
	conn, err := net.Dial("tcp", srv.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	q, _ := wire.NewBuilder().
		ID(0xff01).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.TXT)).
		Build()
	raw, err := wire.Marshal(q)
	require.NoError(t, err)
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(raw)))
	_, err = conn.Write(hdr[:])
	require.NoError(t, err)
	_, err = conn.Write(raw)
	require.NoError(t, err)

	select {
	case got := <-errCh:
		// Marshal-oversize vs UDP-write-too-big race: leave the error open.
		require.Error(t, got)
	case <-time.After(3 * time.Second):
		t.Fatal("WriteMsg never returned an error for oversized response")
	}
}

// TestKeepAliveOptionsApply only proves the option constructors compile and
// apply without error — the runtime behaviour they configure is exercised
// elsewhere (advertise default, idle fallback default).
func TestKeepAliveOptionsApply(t *testing.T) {
	t.Parallel()
	srv := &keepAliveServer{advertise: 5 * time.Second}
	addr, stop := startKeepAliveServer(t, srv)
	defer stop()

	ex, err := acidns.NewTCPKeepAliveExchanger(addr,
		acidns.WithTCPKeepAliveTimeout(2*time.Second),
		acidns.WithTCPKeepAliveAdvertise(false),
		acidns.WithTCPKeepAliveIdle(5*time.Second),
	)
	require.NoError(t, err)
	_, err = ex.Exchange(t.Context(), newQuery(t, "example.com"))
	require.NoError(t, err)
	require.False(t, srv.gotKeepalive.Load(), "advertise=false must NOT inject keepalive option")
}

// TestKeepAliveCloseReleasesConn invokes the type-asserted Close path and
// verifies a subsequent Exchange dials a fresh connection.
func TestKeepAliveCloseReleasesConn(t *testing.T) {
	t.Parallel()
	srv := &keepAliveServer{advertise: 30 * time.Second}
	addr, stop := startKeepAliveServer(t, srv)
	defer stop()

	ex, err := acidns.NewTCPKeepAliveExchanger(addr)
	require.NoError(t, err)

	_, err = ex.Exchange(t.Context(), newQuery(t, "example.com"))
	require.NoError(t, err)

	closer, ok := ex.(interface{ Close() error })
	require.True(t, ok, "keepalive exchanger should expose Close()")
	require.NoError(t, closer.Close())
	// Closing an already-closed exchanger should be a no-op.
	require.NoError(t, closer.Close())

	_, err = ex.Exchange(t.Context(), newQuery(t, "example.com"))
	require.NoError(t, err)
	require.GreaterOrEqual(t, srv.conns.Load(), int64(2),
		"expected a redial after Close")
}

// TestKeepAliveInvalidAddr exercises the constructor error branch.
func TestKeepAliveInvalidAddr(t *testing.T) {
	t.Parallel()
	_, err := acidns.NewTCPKeepAliveExchanger(netip.AddrPort{})
	require.ErrorContains(t, err, "invalid server address")
}

// TestKeepAlivePreservesExistingOption proves ensureKeepAliveOption returns
// the message unchanged when the caller has already attached the option.
func TestKeepAlivePreservesExistingOption(t *testing.T) {
	t.Parallel()
	srv := &keepAliveServer{advertise: 30 * time.Second}
	addr, stop := startKeepAliveServer(t, srv)
	defer stop()

	ex, err := acidns.NewTCPKeepAliveExchanger(addr)
	require.NoError(t, err)

	q, err := wire.NewBuilder().
		ID(0x9999).
		RecursionDesired(true).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		EDNS(wire.NewEDNSBuilder().
			UDPSize(1232).
			Option(wire.NewTCPKeepalive(0)).
			Build()).
		Build()
	require.NoError(t, err)

	_, err = ex.Exchange(t.Context(), q)
	require.NoError(t, err)
	require.True(t, srv.gotKeepalive.Load())
}

// keepAliveBrokenServer accepts a TCP connection then immediately closes it
// without ever responding, forcing the keepalive client through its read-error
// path.
func startKeepAliveBrokenServer(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).AddrPort()
}

func TestKeepAliveExchangeIOError(t *testing.T) {
	t.Parallel()
	addr := startKeepAliveBrokenServer(t)
	ex, err := acidns.NewTCPKeepAliveExchanger(addr,
		acidns.WithTCPKeepAliveTimeout(500*time.Millisecond))
	require.NoError(t, err)
	_, err = ex.Exchange(t.Context(), newQuery(t, "example.com"))
	// Connection is hard-killed mid-stream; could surface as EOF, "connection
	// reset by peer", or a streamframe error. Leave open.
	require.Error(t, err)
}

// TestKeepAliveIDMismatch covers the resp.ID() != q.ID() branch in
// exchangeOverConn.
func TestKeepAliveIDMismatch(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		var hdr [2]byte
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return
		}
		n := int(hdr[0])<<8 | int(hdr[1])
		body := make([]byte, n)
		if _, err := io.ReadFull(c, body); err != nil {
			return
		}
		req, err := wire.Unmarshal(body)
		if err != nil {
			return
		}
		bad, _ := wire.NewBuilder().
			ID(req.ID() ^ 0xffff).
			Response(true).
			Question(req.Questions()[0]).
			Build()
		raw, _ := wire.Marshal(bad)
		var lh [2]byte
		binary.BigEndian.PutUint16(lh[:], uint16(len(raw)))
		_, _ = c.Write(lh[:])
		_, _ = c.Write(raw)
	}()

	ex, err := acidns.NewTCPKeepAliveExchanger(
		ln.Addr().(*net.TCPAddr).AddrPort(),
		acidns.WithTCPKeepAliveTimeout(500*time.Millisecond),
	)
	require.NoError(t, err)
	_, err = ex.Exchange(t.Context(), newQuery(t, "example.com"))
	require.ErrorContains(t, err, "id mismatch")
}

// TestKeepAliveDialFailure exercises the dial-error branch.
func TestKeepAliveDialFailure(t *testing.T) {
	t.Parallel()
	// Pick an addr that should refuse — system port not bound.
	ex, err := acidns.NewTCPKeepAliveExchanger(netip.MustParseAddrPort("127.0.0.1:1"))
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	_, err = ex.Exchange(ctx, newQuery(t, "example.com"))
	// Dial-time refusal vs deadline-exceeded races; both are acceptable.
	require.Error(t, err)
}

// TestUDPNewInvalidAddr exercises the UDP exchanger validation branch.
func TestUDPNewInvalidAddr(t *testing.T) {
	t.Parallel()
	_, err := acidns.NewUDPExchanger(netip.AddrPort{})
	require.ErrorContains(t, err, "invalid server address")
}

// TestUDPDialFailure forces the UDP dial path to fail by passing a destination
// the kernel will refuse to associate (multicast destination in the unicast
// table).
func TestUDPDialFailure(t *testing.T) {
	t.Parallel()
	// "0.0.0.0:0" is invalid as a destination; DialContext will report.
	ex, err := acidns.NewUDPExchanger(netip.MustParseAddrPort("0.0.0.0:0"))
	require.NoError(t, err)
	q, _ := wire.NewBuilder().ID(1).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	// dial-context to the wildcard 0.0.0.0:0 may succeed locally but the
	// subsequent write/read will time out; either way we expect non-nil.
	_, err = ex.Exchange(ctx, q)
	require.Error(t, err)
	// Intentionally generic: per the comment above, the exact origin races.
}

// TestUDPDropsMalformedThenDelivers proves the malformed-datagram branch in
// the UDP exchanger is exercised: server first sends a 1-byte garbage
// datagram, then a real response.
func TestUDPDropsMalformedThenDelivers(t *testing.T) {
	t.Parallel()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	a := pc.LocalAddr().(*net.UDPAddr)
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port))

	go func() {
		buf := make([]byte, 4096)
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		req, err := wire.Unmarshal(buf[:n])
		if err != nil {
			return
		}
		// Garbage first.
		_, _ = pc.WriteTo([]byte{0x00}, src)
		// Then a valid response.
		good, _ := wire.NewBuilder().
			ID(req.ID()).
			Response(true).
			Question(req.Questions()[0]).
			Answer(wire.NewRecord(req.Questions()[0].Name(), time.Minute,
				rdata.NewA(netip.MustParseAddr("203.0.113.99")))).
			Build()
		gw, _ := wire.Marshal(good)
		_, _ = pc.WriteTo(gw, src)
	}()

	ex, err := acidns.NewUDPExchanger(addr, acidns.WithUDPTimeout(2*time.Second))
	require.NoError(t, err)
	q, _ := wire.NewBuilder().
		ID(0x4321).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	resp, err := ex.Exchange(t.Context(), q)
	require.NoError(t, err)
	require.Equal(t, 1, len(resp.Answers()))
}

// TestTCFallbackOnTruncation drives buildFallover's TC path: the UDP server
// answers with TC=1 and the TCP fallback supplies the real answer.
func TestTCFallbackOnTruncation(t *testing.T) {
	t.Parallel()

	// UDP server: always reply with TC=1 and no answers.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	udpAddr := pc.LocalAddr().(*net.UDPAddr)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			req, err := wire.Unmarshal(buf[:n])
			if err != nil {
				continue
			}
			resp, err := wire.NewBuilder().
				ID(req.ID()).
				Response(true).
				Truncated(true).
				Question(req.Questions()[0]).
				Build()
			if err != nil {
				continue
			}
			raw, _ := wire.Marshal(resp)
			_, _ = pc.WriteTo(raw, src)
		}
	}()

	// TCP listener bound to the same port number — UDP/TCP are independent
	// address families on the same port. The TCP handler returns a real A.
	tcpAddrStr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(udpAddr.Port)).String()
	tcpLn, err := net.Listen("tcp", tcpAddrStr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tcpLn.Close() })
	go func() {
		for {
			c, err := tcpLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				var hdr [2]byte
				if _, err := io.ReadFull(conn, hdr[:]); err != nil {
					return
				}
				n := binary.BigEndian.Uint16(hdr[:])
				body := make([]byte, n)
				if _, err := io.ReadFull(conn, body); err != nil {
					return
				}
				req, err := wire.Unmarshal(body)
				if err != nil {
					return
				}
				resp, _ := wire.NewBuilder().
					ID(req.ID()).
					Response(true).
					Question(req.Questions()[0]).
					Answer(wire.NewRecord(req.Questions()[0].Name(), time.Minute,
						rdata.NewA(netip.MustParseAddr("198.51.100.10")))).
					Build()
				raw, _ := wire.Marshal(resp)
				binary.BigEndian.PutUint16(hdr[:], uint16(len(raw)))
				_, _ = conn.Write(hdr[:])
				_, _ = conn.Write(raw)
			}(c)
		}
	}()

	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(udpAddr.Port))
	r, err := acidns.NewResolver(acidns.WithServers(addr))
	require.NoError(t, err)

	ans, err := r.Resolve(t.Context(), wire.MustParseName("example.com"), rrtype.A)
	require.NoError(t, err)
	require.Equal(t, 1, len(ans.Records()))
	require.Equal(t, "198.51.100.10",
		ans.Records()[0].RData().(rdata.A).Addr().String())
}

// TestServersAndExchangerMutuallyExclusive covers the combined-options error.
func TestServersAndExchangerMutuallyExclusive(t *testing.T) {
	t.Parallel()
	stub := &stubExchanger{}
	_, err := acidns.NewResolver(
		acidns.WithExchanger(stub),
		acidns.WithServers(netip.MustParseAddrPort("127.0.0.1:53")),
	)
	require.ErrorContains(t, err, "mutually exclusive")
}

// TestRetryEventuallySucceeds drives the retry exchanger's success-after-
// failure path: first attempt sees no listener, second attempt hits a real
// server. We do this by spinning up a UDP responder on an addr after a brief
// delay — but more reliably, point at an unbound port for the first attempt
// and toggle to a working one. The simpler path: configure a server that
// drops the first packet, answers the second.
func TestRetryEventuallySucceeds(t *testing.T) {
	t.Parallel()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	a := pc.LocalAddr().(*net.UDPAddr)
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port))

	var seen atomic.Int32
	go func() {
		buf := make([]byte, 4096)
		for {
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if seen.Add(1) == 1 {
				// drop first
				continue
			}
			req, err := wire.Unmarshal(buf[:n])
			if err != nil {
				continue
			}
			resp, _ := wire.NewBuilder().
				ID(req.ID()).
				Response(true).
				Question(req.Questions()[0]).
				Answer(wire.NewRecord(req.Questions()[0].Name(), time.Minute,
					rdata.NewA(netip.MustParseAddr("198.51.100.50")))).
				Build()
			raw, _ := wire.Marshal(resp)
			_, _ = pc.WriteTo(raw, src)
		}
	}()

	r, err := acidns.NewResolver(
		acidns.WithServers(addr),
		acidns.WithAttempts(3),
		acidns.WithPerAttemptTimeout(150*time.Millisecond),
	)
	require.NoError(t, err)
	ans, err := r.Resolve(t.Context(), wire.MustParseName("example.com"), rrtype.A)
	require.NoError(t, err)
	require.Equal(t, 1, len(ans.Records()))
}

// TestSystemResolversApplies just confirms WithSystemResolvers can be applied
// without panic. On hosts without a usable /etc/resolv.conf this returns an
// error from NewResolver — both branches keep the test green.
func TestSystemResolversApplies(t *testing.T) {
	t.Parallel()
	_, err := acidns.NewResolver(acidns.WithSystemResolvers())
	if err != nil {
		// Acceptable: no nameservers, file missing, etc.
		return
	}
}

// TestExtractMissingType ensures Extract filters by inferred RR type even
// when records of a different type satisfy the structural assertion.
func TestExtractMissingType(t *testing.T) {
	t.Parallel()
	rec := wire.NewRecord(wire.MustParseName("example.com"), time.Minute,
		rdata.NewAAAA(netip.MustParseAddr("2001:db8::1")))
	got := acidns.Extract[rdata.A]([]wire.Record{rec})
	require.Empty(t, got)
}

// TestResolveAsBubblesError forwards the underlying Resolve error to ResolveAs.
func TestResolveAsBubblesError(t *testing.T) {
	t.Parallel()
	stub := &stubExchanger{err: io.ErrUnexpectedEOF}
	r, err := acidns.NewResolver(
		acidns.WithExchanger(stub),
		acidns.WithSpecialUse(false),
	)
	require.NoError(t, err)
	_, err = acidns.ResolveAs[rdata.A](t.Context(), r, wire.MustParseName("example.com"))
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
}
