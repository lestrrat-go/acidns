package dot_test

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
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/dot"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// startDoT starts a TLS-backed DNS responder on 127.0.0.1.
func startDoT(t *testing.T) (netip.AddrPort, *tls.Config) {
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
	clientCfg := &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}

	srvCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				var lenBuf [2]byte
				if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
					return
				}
				n := binary.BigEndian.Uint16(lenBuf[:])
				body := make([]byte, n)
				if _, err := io.ReadFull(c, body); err != nil {
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
						rdata.NewA(netip.MustParseAddr("198.51.100.42")))).
					Build()
				wire, _ := wire.Marshal(resp)
				binary.BigEndian.PutUint16(lenBuf[:], uint16(len(wire)))
				_, _ = c.Write(lenBuf[:])
				_, _ = c.Write(wire)
			}(conn)
		}
	}()

	a := ln.Addr().(*net.TCPAddr)
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port)), clientCfg
}

func TestDoTExchange(t *testing.T) {
	t.Parallel()

	addr, cfg := startDoT(t)
	ex, err := dot.New(addr, dot.WithTLSConfig(cfg), dot.WithServerName("127.0.0.1"))
	require.NoError(t, err)

	q, _ := wire.NewBuilder().
		ID(0xaa55).
		RecursionDesired(true).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()

	resp, err := ex.Exchange(t.Context(), q)
	require.NoError(t, err)
	require.Equal(t, q.ID(), resp.ID())
	require.Equal(t, "198.51.100.42", resp.Answers()[0].RData().(rdata.A).Addr().String())
}

func TestDoTContextCancel(t *testing.T) {
	t.Parallel()

	// A non-TLS listener: TLS handshake will hang/error.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	a := ln.Addr().(*net.TCPAddr)
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port))

	ex, err := dot.New(addr, dot.WithServerName("127.0.0.1"))
	require.NoError(t, err)

	q, _ := wire.NewBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	_, err = ex.Exchange(ctx, q)
	// TLS handshake against a plain TCP listener: surfaces as "first record
	// does not look like a TLS handshake" or context.DeadlineExceeded
	// depending on timing — accept either via generic check.
	require.Error(t, err)
}

// TestDoTNewInvalidAddr exercises the rejected-zero-address branch of New.
func TestDoTNewInvalidAddr(t *testing.T) {
	t.Parallel()

	_, err := dot.New(netip.AddrPort{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid server address")
}

// TestDoTNewDefaultServerName exercises the branch where neither
// WithServerName nor a pre-set ServerName on a custom TLS config is given,
// so New falls back to the address's host part.
func TestDoTNewDefaultServerName(t *testing.T) {
	t.Parallel()

	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 853)
	ex, err := dot.New(addr)
	require.NoError(t, err)
	require.NotNil(t, ex)

	// And again with a TLSConfig that has an empty ServerName: should still
	// fall through to the address-derived default.
	ex2, err := dot.New(addr, dot.WithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12}))
	require.NoError(t, err)
	require.NotNil(t, ex2)
}

// TestDoTNewPresetTLSConfigServerName: providing a tls.Config that already
// has ServerName set, with no WithServerName option, should leave it alone.
func TestDoTNewPresetTLSConfigServerName(t *testing.T) {
	t.Parallel()

	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 853)
	ex, err := dot.New(addr, dot.WithTLSConfig(&tls.Config{
		ServerName: "preset.example",
		MinVersion: tls.VersionTLS12,
	}))
	require.NoError(t, err)
	require.NotNil(t, ex)
}

// TestDoTStreamDialError covers the dial-error branch of Stream by pointing
// at a TCP port that has been closed before the call runs.
func TestDoTStreamDialError(t *testing.T) {
	t.Parallel()

	// Bind, immediately close — port should refuse connections.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	a := ln.Addr().(*net.TCPAddr)
	require.NoError(t, ln.Close())
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port))

	ex, err := dot.New(addr, dot.WithServerName("127.0.0.1"), dot.WithTimeout(200*time.Millisecond))
	require.NoError(t, err)

	q, _ := wire.NewBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()

	se, ok := ex.(acidns.StreamExchanger)
	require.True(t, ok)
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	_, err = se.Stream(ctx, q)
	require.Error(t, err)
	require.Contains(t, err.Error(), "dot: dial")
}

// TestDoTStreamWriteError covers the NewConnStream error path: a TLS
// listener that completes the handshake then closes the connection without
// reading, so the framed-write of the question fails.
func TestDoTStreamWriteError(t *testing.T) {
	t.Parallel()

	addr, cfg := startDoTHandshakeOnly(t)
	ex, err := dot.New(addr,
		dot.WithTLSConfig(cfg),
		dot.WithServerName("127.0.0.1"),
		dot.WithTimeout(500*time.Millisecond),
	)
	require.NoError(t, err)

	q, _ := wire.NewBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()

	se, ok := ex.(acidns.StreamExchanger)
	require.True(t, ok)
	// Allow a generous timeout — the failure mode here is the server
	// closing the connection mid-write or reset on first read.
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	stream, err := se.Stream(ctx, q)
	if err != nil {
		// NewConnStream surfaced the close directly — desired path.
		require.Contains(t, err.Error(), "dot:")
		return
	}
	// Write may have succeeded into the kernel buffer before the peer's
	// FIN was observed. In that case Next must report the EOF — though the
	// exact wrap (io.EOF, "use of closed network connection", "broken pipe")
	// depends on timing, so we accept any error.
	defer func() { _ = stream.Close() }()
	_, nerr := stream.Next(ctx)
	require.Error(t, nerr)
}

// startDoTHandshakeOnly accepts TLS connections, completes the handshake,
// then immediately closes — used to exercise post-handshake I/O failures.
func startDoTHandshakeOnly(t *testing.T) (netip.AddrPort, *tls.Config) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
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
	clientCfg := &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}

	srvCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Force the TLS handshake to complete, then drop.
			if tc, ok := conn.(*tls.Conn); ok {
				_ = tc.Handshake()
			}
			_ = conn.Close()
		}
	}()

	a := ln.Addr().(*net.TCPAddr)
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port)), clientCfg
}
