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
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dot"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// startMultiDoT starts a TLS-backed responder that handles multiple
// queries per connection — same fixture shape as startDoT but the
// connection-handler loop reads frames until the client closes. The
// server also counts the number of inbound TCP connections so tests
// can verify the keep-alive Client reuses one across exchanges.
func startMultiDoT(t *testing.T, idleTimeout time.Duration) (netip.AddrPort, *tls.Config, *atomic.Int32) {
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

	var connCount atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			connCount.Add(1)
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				for {
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
					eb := wire.NewEDNSBuilder().UDPSize(1232)
					if idleTimeout > 0 {
						eb = eb.Option(wire.NewTCPKeepalive(idleTimeout))
					}
					ar, err := rdata.NewA(netip.MustParseAddr("198.51.100.99"))
					require.NoError(t, err)
					resp, _ := wire.NewMessageBuilder().
						ID(req.ID()).
						Response(true).
						Question(req.Questions()[0]).
						Answer(wire.NewRecord(req.Questions()[0].Name(), time.Minute,
							ar)).
						EDNS(mustEDNS(t, eb)).
						Build()
					out, _ := wire.Marshal(resp)
					binary.BigEndian.PutUint16(lenBuf[:], uint16(len(out)))
					_, _ = c.Write(lenBuf[:])
					_, _ = c.Write(out)
				}
			}(conn)
		}
	}()

	a := ln.Addr().(*net.TCPAddr)
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port)), clientCfg, &connCount
}

func TestDoTKeepAliveReusesConnection(t *testing.T) {
	t.Parallel()

	addr, cfg, conns := startMultiDoT(t, time.Minute)
	ex, err := dot.NewKeepAliveExchanger(addr,
		dot.WithKeepAliveTLSConfig(cfg),
		dot.WithKeepAliveServerName("127.0.0.1"),
		dot.WithKeepAlivePadding(false),
	)
	require.NoError(t, err)

	mkQuery := func(id uint16) wire.Message {
		q, _ := wire.NewMessageBuilder().
			ID(id).
			Question(wire.NewQuestion(wire.MustParseName("a.example."), rrtype.A)).
			Build()
		return q
	}

	for id := uint16(1); id <= 5; id++ {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		resp, err := ex.Exchange(ctx, mkQuery(id))
		cancel()
		require.NoError(t, err)
		require.Equal(t, id, resp.ID())
	}

	require.EqualValues(t, 1, conns.Load(),
		"five exchanges should reuse a single TLS connection, got %d", conns.Load())
}

func TestDoTKeepAliveExpiresIdleConnection(t *testing.T) {
	t.Parallel()

	// Server advertises no keepalive option → the client's local
	// idle-fallback governs reuse. A tiny fallback forces the second
	// exchange to dial fresh.
	addr, cfg, conns := startMultiDoT(t, 0)
	ex, err := dot.NewKeepAliveExchanger(addr,
		dot.WithKeepAliveTLSConfig(cfg),
		dot.WithKeepAliveServerName("127.0.0.1"),
		dot.WithKeepAliveIdle(time.Nanosecond),
		dot.WithKeepAlivePadding(false),
	)
	require.NoError(t, err)

	mkQuery := func(id uint16) wire.Message {
		q, _ := wire.NewMessageBuilder().
			ID(id).
			Question(wire.NewQuestion(wire.MustParseName("a.example."), rrtype.A)).
			Build()
		return q
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err = ex.Exchange(ctx, mkQuery(1))
	require.NoError(t, err)
	// Sleep a hair so the deadline is observably expired.
	time.Sleep(time.Millisecond)
	_, err = ex.Exchange(ctx, mkQuery(2))
	require.NoError(t, err)

	require.GreaterOrEqual(t, conns.Load(), int32(2),
		"sub-millisecond idle must force a fresh dial; got %d", conns.Load())
}

func TestDoTKeepAliveRefusesIPLiteralWithoutServerName(t *testing.T) {
	t.Parallel()
	addr := netip.MustParseAddrPort("127.0.0.1:853")
	_, err := dot.NewKeepAliveExchanger(addr)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ServerName")
}
