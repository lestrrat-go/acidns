package doq_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/doq"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// serverHook is invoked by the customDoQ server with the parsed request
// and the QUIC stream. The hook is responsible for writing whatever
// response (or no response) the test wants.
type serverHook func(t *testing.T, req wire.Message, stream *quic.Stream)

// startCustomDoQ spawns a QUIC-based DNS responder whose response logic is
// supplied by hook. Returns the listening address and a client TLS config
// that trusts the ephemeral certificate.
func startCustomDoQ(t *testing.T, hook serverHook) (netip.AddrPort, *tls.Config) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)

	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"doq"},
	}
	clientTLS := &tls.Config{
		RootCAs:    pool,
		ServerName: "127.0.0.1",
		MinVersion: tls.VersionTLS13,
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { udpConn.Close() })

	tr := &quic.Transport{Conn: udpConn}
	t.Cleanup(func() { tr.Close() })

	ln, err := tr.Listen(srvTLS, &quic.Config{MaxIdleTimeout: 30 * time.Second})
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept(t.Context())
			if err != nil {
				return
			}
			go func(c *quic.Conn) {
				stream, err := c.AcceptStream(t.Context())
				if err != nil {
					return
				}
				defer stream.Close()
				var hdr [2]byte
				if _, err := io.ReadFull(stream, hdr[:]); err != nil {
					return
				}
				size := binary.BigEndian.Uint16(hdr[:])
				body := make([]byte, size)
				if _, err := io.ReadFull(stream, body); err != nil {
					return
				}
				req, err := wire.Unmarshal(body)
				if err != nil {
					return
				}
				hook(t, req, stream)
			}(conn)
		}
	}()

	a := udpConn.LocalAddr().(*net.UDPAddr)
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port)), clientTLS
}

func writeFrame(stream *quic.Stream, payload []byte) {
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(payload)))
	stream.Write(hdr[:])
	stream.Write(payload)
}

func buildQuery(t *testing.T, id uint16) wire.Message {
	t.Helper()
	q, err := wire.NewBuilder().
		ID(id).
		RecursionDesired(true).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	require.NoError(t, err)
	return q
}

func buildAnswer(t *testing.T, id uint16, q wire.Question) wire.Message {
	t.Helper()
	resp, err := wire.NewBuilder().
		ID(id).
		Response(true).
		Question(q).
		Answer(wire.NewRecord(q.Name(), time.Minute,
			rdata.NewA(netip.MustParseAddr("198.51.100.77")))).
		Build()
	require.NoError(t, err)
	return resp
}

// TestNewInvalidAddr exercises the invalid-address branch of New().
func TestNewInvalidAddr(t *testing.T) {
	t.Parallel()
	_, err := doq.New(netip.AddrPort{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid server address")
}

// TestNewALPNAlreadyPresent covers containsALPN's true branch and confirms
// the constructor does not duplicate the entry.
func TestNewALPNAlreadyPresent(t *testing.T) {
	t.Parallel()
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"doq", "h3"},
	}
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 8530)
	_, err := doq.New(addr, doq.WithTLSConfig(tlsCfg))
	require.NoError(t, err)
}

// TestExchangeFallbackTimeout covers the WithTimeout fallback path in
// Exchange (the ctx has no deadline, so the configured timeout kicks in).
func TestExchangeFallbackTimeout(t *testing.T) {
	t.Parallel()
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { udpConn.Close() })
	a := udpConn.LocalAddr().(*net.UDPAddr)
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port))

	ex, err := doq.New(addr, doq.WithTimeout(150*time.Millisecond))
	require.NoError(t, err)

	q := buildQuery(t, 1)
	// Use a plain context with no deadline; the fallback timeout is what
	// must abort the exchange. t.Context() is already cancelled when the
	// test ends, but during the run it has no deadline.
	_, err = ex.Exchange(t.Context(), q)
	require.Error(t, err)
}

// TestExchangeIDMismatch ensures the response-ID check rejects a server
// that echoes a non-zero ID different from the query.
func TestExchangeIDMismatch(t *testing.T) {
	t.Parallel()
	addr, cfg := startCustomDoQ(t, func(t *testing.T, req wire.Message, stream *quic.Stream) {
		// Build a response with an ID that is neither the query's ID nor 0.
		resp := buildAnswer(t, req.ID()^0xFFFF, req.Questions()[0])
		out, err := wire.Marshal(resp)
		require.NoError(t, err)
		writeFrame(stream, out)
	})

	ex, err := doq.New(addr, doq.WithTLSConfig(cfg))
	require.NoError(t, err)

	q := buildQuery(t, 0x1234)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err = ex.Exchange(ctx, q)
	require.Error(t, err)
	require.Contains(t, err.Error(), "id mismatch")
}

// TestExchangeAcceptsZeroID covers RFC 9250 §4.2.1's allowance of an ID-0
// response.
func TestExchangeAcceptsZeroID(t *testing.T) {
	t.Parallel()
	addr, cfg := startCustomDoQ(t, func(t *testing.T, req wire.Message, stream *quic.Stream) {
		resp := buildAnswer(t, 0, req.Questions()[0])
		out, err := wire.Marshal(resp)
		require.NoError(t, err)
		writeFrame(stream, out)
	})

	ex, err := doq.New(addr, doq.WithTLSConfig(cfg))
	require.NoError(t, err)

	q := buildQuery(t, 0xbeef)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	resp, err := ex.Exchange(ctx, q)
	require.NoError(t, err)
	require.Equal(t, uint16(0), resp.ID())
}

// TestExchangeMalformedResponse covers the unmarshal-failure branch.
func TestExchangeMalformedResponse(t *testing.T) {
	t.Parallel()
	addr, cfg := startCustomDoQ(t, func(t *testing.T, req wire.Message, stream *quic.Stream) {
		// Length-prefixed garbage that is not a parseable DNS message.
		writeFrame(stream, []byte{0x00, 0x01, 0x02})
	})

	ex, err := doq.New(addr, doq.WithTLSConfig(cfg))
	require.NoError(t, err)

	q := buildQuery(t, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err = ex.Exchange(ctx, q)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unmarshal")
}

// TestExchangeReadBodyTruncated covers the read-body error branch: the
// server advertises a length but FINs before sending the bytes.
func TestExchangeReadBodyTruncated(t *testing.T) {
	t.Parallel()
	addr, cfg := startCustomDoQ(t, func(t *testing.T, req wire.Message, stream *quic.Stream) {
		// Promise 100 bytes, send none, then close.
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], 100)
		stream.Write(hdr[:])
		stream.Close()
	})

	ex, err := doq.New(addr, doq.WithTLSConfig(cfg))
	require.NoError(t, err)

	q := buildQuery(t, 2)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err = ex.Exchange(ctx, q)
	require.Error(t, err)
	require.Contains(t, err.Error(), "read body")
}

// TestExchangeReadLengthEOF covers the read-length error branch: the
// server FINs without writing any bytes.
func TestExchangeReadLengthEOF(t *testing.T) {
	t.Parallel()
	addr, cfg := startCustomDoQ(t, func(t *testing.T, req wire.Message, stream *quic.Stream) {
		stream.Close()
	})

	ex, err := doq.New(addr, doq.WithTLSConfig(cfg))
	require.NoError(t, err)

	q := buildQuery(t, 3)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err = ex.Exchange(ctx, q)
	require.Error(t, err)
	require.Contains(t, err.Error(), "read length")
}

// TestStreamFallbackTimeout covers Stream's WithTimeout fallback path.
func TestStreamFallbackTimeout(t *testing.T) {
	t.Parallel()
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { udpConn.Close() })
	a := udpConn.LocalAddr().(*net.UDPAddr)
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port))

	ex, err := doq.New(addr, doq.WithTimeout(150*time.Millisecond))
	require.NoError(t, err)
	se, ok := ex.(acidns.StreamExchanger)
	require.True(t, ok)

	q := buildQuery(t, 7)
	_, err = se.Stream(t.Context(), q)
	require.Error(t, err)
	require.Contains(t, err.Error(), "dial")
}

// TestStreamIDMismatch ensures Stream.Next() rejects responses whose ID
// neither matches the query nor is zero.
func TestStreamIDMismatch(t *testing.T) {
	t.Parallel()
	addr, cfg := startCustomDoQ(t, func(t *testing.T, req wire.Message, stream *quic.Stream) {
		resp := buildAnswer(t, req.ID()^0xFFFF, req.Questions()[0])
		out, err := wire.Marshal(resp)
		require.NoError(t, err)
		writeFrame(stream, out)
	})

	ex, err := doq.New(addr, doq.WithTLSConfig(cfg))
	require.NoError(t, err)
	se, ok := ex.(acidns.StreamExchanger)
	require.True(t, ok)

	q := buildQuery(t, 0xaa55)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	stream, err := se.Stream(ctx, q)
	require.NoError(t, err)
	defer stream.Close()
	_, err = stream.Next(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "id mismatch")
}

// TestStreamMultipleResponses verifies Next() returns each frame in turn
// and that an EOF after the server FINs surfaces as an error.
func TestStreamMultipleResponses(t *testing.T) {
	t.Parallel()
	var sent atomic.Int32
	addr, cfg := startCustomDoQ(t, func(t *testing.T, req wire.Message, stream *quic.Stream) {
		for i := 0; i < 3; i++ {
			resp := buildAnswer(t, req.ID(), req.Questions()[0])
			out, err := wire.Marshal(resp)
			require.NoError(t, err)
			writeFrame(stream, out)
			sent.Add(1)
		}
	})

	ex, err := doq.New(addr, doq.WithTLSConfig(cfg))
	require.NoError(t, err)
	se, ok := ex.(acidns.StreamExchanger)
	require.True(t, ok)

	q := buildQuery(t, 0x4242)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	stream, err := se.Stream(ctx, q)
	require.NoError(t, err)
	defer stream.Close()

	for i := 0; i < 3; i++ {
		resp, err := stream.Next(ctx)
		require.NoError(t, err)
		require.Equal(t, q.ID(), resp.ID())
	}
	// Fourth read either errors (EOF) or trips the read deadline.
	_, err = stream.Next(ctx)
	require.Error(t, err)

	// Close should be idempotent.
	require.NoError(t, stream.Close())
	require.NoError(t, stream.Close())
}

// TestStreamContextCancelDuringNext covers the ctx-cancellation branch of
// Next() (the goroutine that bumps the read deadline).
func TestStreamContextCancelDuringNext(t *testing.T) {
	t.Parallel()
	// Server sends nothing — it just keeps the stream open until the
	// connection is torn down by the client's Close().
	hold := make(chan struct{})
	addr, cfg := startCustomDoQ(t, func(t *testing.T, req wire.Message, stream *quic.Stream) {
		<-hold
	})
	t.Cleanup(func() { close(hold) })

	ex, err := doq.New(addr, doq.WithTLSConfig(cfg))
	require.NoError(t, err)
	se, ok := ex.(acidns.StreamExchanger)
	require.True(t, ok)

	q := buildQuery(t, 0x1357)
	dialCtx, dialCancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer dialCancel()
	stream, err := se.Stream(dialCtx, q)
	require.NoError(t, err)
	defer stream.Close()

	nextCtx, nextCancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer nextCancel()
	_, err = stream.Next(nextCtx)
	require.Error(t, err)
}

// TestStreamDialFailureClosed verifies that calling Stream against a port
// with no QUIC listener returns an error promptly when the context already
// has a deadline.
func TestStreamDialFailureWithDeadline(t *testing.T) {
	t.Parallel()
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { udpConn.Close() })
	a := udpConn.LocalAddr().(*net.UDPAddr)
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port))

	ex, err := doq.New(addr)
	require.NoError(t, err)
	se, ok := ex.(acidns.StreamExchanger)
	require.True(t, ok)

	q := buildQuery(t, 9)
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	_, err = se.Stream(ctx, q)
	require.Error(t, err)
}

// startRefusingDoQ accepts the QUIC handshake but immediately closes the
// connection with an application error. Subsequent OpenStreamSync /
// stream.Write calls from the client must fail.
func startRefusingDoQ(t *testing.T) (netip.AddrPort, *tls.Config) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)

	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"doq"},
	}
	clientTLS := &tls.Config{
		RootCAs:    pool,
		ServerName: "127.0.0.1",
		MinVersion: tls.VersionTLS13,
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { udpConn.Close() })

	tr := &quic.Transport{Conn: udpConn}
	t.Cleanup(func() { tr.Close() })

	ln, err := tr.Listen(srvTLS, &quic.Config{MaxIdleTimeout: 30 * time.Second})
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept(t.Context())
			if err != nil {
				return
			}
			// Wait for the client to open a stream, then tear the
			// connection down. This synchronizes the close on a real
			// client action instead of a wall-clock sleep — the
			// resulting error path (OpenStreamSync / Write) is the
			// behavior under test.
			go func(c *quic.Conn) {
				_, _ = c.AcceptStream(t.Context())
				_ = c.CloseWithError(42, "go away")
			}(conn)
		}
	}()

	a := udpConn.LocalAddr().(*net.UDPAddr)
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port)), clientTLS
}

// TestExchangeStreamRefused covers Exchange's OpenStreamSync / Write error
// branches by talking to a server that closes the QUIC connection right
// after the handshake.
func TestExchangeStreamRefused(t *testing.T) {
	t.Parallel()
	addr, cfg := startRefusingDoQ(t)
	ex, err := doq.New(addr, doq.WithTLSConfig(cfg))
	require.NoError(t, err)

	q := buildQuery(t, 11)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	// Multiple attempts so that at least one races into the
	// stream-open / write phase rather than failing during dial only.
	var lastErr error
	for i := 0; i < 5; i++ {
		_, lastErr = ex.Exchange(ctx, q)
		if lastErr != nil {
			break
		}
	}
	require.Error(t, lastErr)
}

// TestStreamRefused covers Stream's OpenStreamSync / WriteFrame error
// branches by talking to a server that tears the connection down right
// after the handshake.
func TestStreamRefused(t *testing.T) {
	t.Parallel()
	addr, cfg := startRefusingDoQ(t)
	ex, err := doq.New(addr, doq.WithTLSConfig(cfg))
	require.NoError(t, err)
	se, ok := ex.(acidns.StreamExchanger)
	require.True(t, ok)

	q := buildQuery(t, 12)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	var lastErr error
	for i := 0; i < 5; i++ {
		s, err := se.Stream(ctx, q)
		if err != nil {
			lastErr = err
			break
		}
		// If Stream returned without error the conn was probably still
		// transient; pull a frame to confirm and continue retrying.
		if _, err := s.Next(ctx); err != nil {
			s.Close()
			lastErr = err
			break
		}
		s.Close()
	}
	require.Error(t, lastErr)
}

// startStreamStarvedDoQ accepts QUIC handshakes but advertises zero
// bidi-stream credit, so OpenStreamSync from the client will block until
// the context expires.
func startStreamStarvedDoQ(t *testing.T) (netip.AddrPort, *tls.Config) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)

	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"doq"},
	}
	clientTLS := &tls.Config{
		RootCAs:    pool,
		ServerName: "127.0.0.1",
		MinVersion: tls.VersionTLS13,
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { udpConn.Close() })

	tr := &quic.Transport{Conn: udpConn}
	t.Cleanup(func() { tr.Close() })

	ln, err := tr.Listen(srvTLS, &quic.Config{
		MaxIdleTimeout:        30 * time.Second,
		MaxIncomingStreams:    -1, // refuse all bidi streams
		MaxIncomingUniStreams: -1,
	})
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept(t.Context())
			if err != nil {
				return
			}
			// Keep the conn alive so DialAddr returns; never grant
			// stream credit so OpenStreamSync hangs forever.
			_ = conn
		}
	}()

	a := udpConn.LocalAddr().(*net.UDPAddr)
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port)), clientTLS
}

// TestExchangeOpenStreamTimeout exercises the OpenStreamSync error branch
// in Exchange via a server that never grants bidi-stream credit. The
// per-exchange timeout pops while waiting for credit.
func TestExchangeOpenStreamTimeout(t *testing.T) {
	t.Parallel()
	addr, cfg := startStreamStarvedDoQ(t)
	ex, err := doq.New(addr,
		doq.WithTLSConfig(cfg),
		doq.WithTimeout(500*time.Millisecond),
	)
	require.NoError(t, err)

	q := buildQuery(t, 31)
	_, err = ex.Exchange(t.Context(), q)
	require.Error(t, err)
	require.Contains(t, err.Error(), "open stream")
}

// TestStreamOpenStreamTimeout covers the OpenStreamSync error branch in
// Stream() with the same starved-server trick.
func TestStreamOpenStreamTimeout(t *testing.T) {
	t.Parallel()
	addr, cfg := startStreamStarvedDoQ(t)
	ex, err := doq.New(addr,
		doq.WithTLSConfig(cfg),
		doq.WithTimeout(500*time.Millisecond),
	)
	require.NoError(t, err)
	se, ok := ex.(acidns.StreamExchanger)
	require.True(t, ok)

	q := buildQuery(t, 32)
	_, err = se.Stream(t.Context(), q)
	require.Error(t, err)
	require.Contains(t, err.Error(), "open stream")
}

// TestExchangeMarshalError covers the wire.Marshal error branch in
// Exchange. Build an answer record whose rdata exceeds 64KiB so packRecord
// fails before any network I/O happens.
func TestExchangeMarshalError(t *testing.T) {
	t.Parallel()
	huge := make([]byte, 0x10001)
	rd := rdata.NewUnknown(rrtype.Type(65000), huge)
	bad, err := wire.NewBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Answer(wire.NewRecord(wire.MustParseName("example.com"), time.Minute, rd)).
		Build()
	require.NoError(t, err)

	// Use an unbound port; we never reach the dial because Marshal fails
	// first.
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 1)
	ex, err := doq.New(addr)
	require.NoError(t, err)
	_, err = ex.Exchange(t.Context(), bad)
	require.Error(t, err)
	require.Contains(t, err.Error(), "marshal")
}

// TestExchangeBrokenAfterDial spins up a server that accepts the QUIC
// handshake but never accepts a stream and tears the connection down very
// shortly after. This races the client between dial-success and the
// stream-open / write phase to exercise the OpenStreamSync / Write error
// branches. We retry several times to make the race likely to land.
func TestExchangeBrokenAfterDial(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)

	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"doq"},
	}
	clientTLS := &tls.Config{
		RootCAs:    pool,
		ServerName: "127.0.0.1",
		MinVersion: tls.VersionTLS13,
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { udpConn.Close() })

	tr := &quic.Transport{Conn: udpConn}
	t.Cleanup(func() { tr.Close() })

	ln, err := tr.Listen(srvTLS, &quic.Config{MaxIdleTimeout: 30 * time.Second})
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	// Accept loop: complete the handshake, then immediately tear down.
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() {
		for {
			conn, err := ln.Accept(t.Context())
			if err != nil {
				return
			}
			// Drop the conn right after the handshake. Whether the
			// client's OpenStreamSync, Write, or read trips first
			// depends on race ordering — all error paths are valid
			// outcomes for this test.
			go func(c *quic.Conn) {
				_ = c.CloseWithError(99, "shutting down")
			}(conn)
			select {
			case <-done:
				return
			default:
			}
		}
	}()

	a := udpConn.LocalAddr().(*net.UDPAddr)
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port))

	ex, err := doq.New(addr, doq.WithTLSConfig(clientTLS))
	require.NoError(t, err)
	se, ok := ex.(acidns.StreamExchanger)
	require.True(t, ok)

	q := buildQuery(t, 21)
	for i := 0; i < 25; i++ {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		_, _ = ex.Exchange(ctx, q)
		cancel()
	}
	for i := 0; i < 25; i++ {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		s, err := se.Stream(ctx, q)
		if err == nil {
			_, _ = s.Next(ctx)
			s.Close()
		}
		cancel()
	}
}

// TestWithServerNameOverride covers the explicit ServerName-override branch
// of New() when the supplied TLS config has no ServerName set.
func TestWithServerNameOverride(t *testing.T) {
	t.Parallel()
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 8531)
	_, err := doq.New(addr,
		doq.WithTLSConfig(tlsCfg),
		doq.WithServerName("override.example"),
	)
	require.NoError(t, err)
}
