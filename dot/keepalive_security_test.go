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

	"github.com/lestrrat-go/acidns/dot"
	"github.com/lestrrat-go/acidns/internal/spki"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// startMultiDoTWithCert mirrors startMultiDoT but additionally returns
// the parsed leaf certificate so tests can compute the SPKI pin.
func startMultiDoTWithCert(t *testing.T) (netip.AddrPort, *tls.Config, *x509.Certificate) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ka-pin-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	keyDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	clientCfg := &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13}

	srvCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
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
					ar, err := rdata.NewA(netip.MustParseAddr("198.51.100.7"))
					if err != nil {
						return
					}
					resp, _ := wire.NewMessageBuilder().
						ID(req.ID()).
						Response(true).
						Question(req.Questions()[0]).
						Answer(wire.NewRecord(req.Questions()[0].Name(), time.Minute, ar)).
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
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port)), clientCfg, leaf
}

func mkKAQuery(t *testing.T, id uint16) wire.Message {
	t.Helper()
	q, err := wire.NewMessageBuilder().
		ID(id).
		RecursionDesired(true).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	require.NoError(t, err)
	return q
}

func TestKeepAliveSPKIPinMatch(t *testing.T) {
	t.Parallel()
	addr, cfg, leaf := startMultiDoTWithCert(t)
	pin := spki.Hash(leaf)

	ex, err := dot.NewKeepAliveExchanger(addr,
		dot.WithKeepAliveTLSConfig(cfg),
		dot.WithKeepAliveServerName("127.0.0.1"),
		dot.WithKeepAlivePadding(false),
		dot.WithKeepAliveSPKIPin(pin[:]),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	resp, err := ex.Exchange(ctx, mkKAQuery(t, 0xa11c))
	require.NoError(t, err)
	require.Equal(t, uint16(0xa11c), resp.ID())
}

func TestKeepAliveSPKIPinMismatch(t *testing.T) {
	t.Parallel()
	addr, cfg, _ := startMultiDoTWithCert(t)

	wrongPin := make([]byte, spki.HashSize) // all zeros
	ex, err := dot.NewKeepAliveExchanger(addr,
		dot.WithKeepAliveTLSConfig(cfg),
		dot.WithKeepAliveServerName("127.0.0.1"),
		dot.WithKeepAlivePadding(false),
		dot.WithKeepAliveSPKIPin(wrongPin),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err = ex.Exchange(ctx, mkKAQuery(t, 0xb22d))
	require.ErrorIs(t, err, dot.ErrSPKIPinMismatch)
}

func TestKeepAliveSPKIPinInvalidLength(t *testing.T) {
	t.Parallel()
	addr := netip.MustParseAddrPort("127.0.0.1:853")
	_, err := dot.NewKeepAliveExchanger(addr,
		dot.WithKeepAliveServerName("test"),
		dot.WithKeepAliveSPKIPin(make([]byte, 16)),
	)
	require.ErrorIs(t, err, dot.ErrInvalidSPKIPin)
}

func TestKeepAliveSPKIPinPreservesCallerVerifyConnection(t *testing.T) {
	t.Parallel()
	addr, cfg, leaf := startMultiDoTWithCert(t)
	pin := spki.Hash(leaf)

	callerErr := io.ErrClosedPipe
	cfg = cfg.Clone()
	cfg.VerifyConnection = func(_ tls.ConnectionState) error { return callerErr }

	ex, err := dot.NewKeepAliveExchanger(addr,
		dot.WithKeepAliveTLSConfig(cfg),
		dot.WithKeepAliveServerName("127.0.0.1"),
		dot.WithKeepAlivePadding(false),
		dot.WithKeepAliveSPKIPin(pin[:]),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err = ex.Exchange(ctx, mkKAQuery(t, 0xc33e))
	require.ErrorIs(t, err, callerErr)
}

func TestKeepAliveRejectsInsecureTLSConfig(t *testing.T) {
	t.Parallel()
	addr := netip.MustParseAddrPort("127.0.0.1:853")
	cfg := &tls.Config{InsecureSkipVerify: true, ServerName: "example"}

	_, err := dot.NewKeepAliveExchanger(addr,
		dot.WithKeepAliveTLSConfig(cfg),
		dot.WithKeepAliveServerName("example"),
	)
	require.ErrorIs(t, err, dot.ErrInsecureTLSConfig)
}

func TestKeepAliveAllowsInsecureTLSConfigWithExplicitOptIn(t *testing.T) {
	t.Parallel()
	addr := netip.MustParseAddrPort("127.0.0.1:853")
	cfg := &tls.Config{InsecureSkipVerify: true, ServerName: "example"}

	_, err := dot.NewKeepAliveExchanger(addr,
		dot.WithKeepAliveTLSConfig(cfg),
		dot.WithKeepAliveServerName("example"),
		dot.WithKeepAliveInsecure(true),
	)
	require.NoError(t, err)
}

func TestKeepAliveInsecureSkipsServerNameCheck(t *testing.T) {
	t.Parallel()
	// No ServerName supplied; with WithKeepAliveInsecure(true) the
	// constructor must NOT refuse — symmetric with the single-shot
	// New(WithInsecure(true)) escape hatch for loopback testing.
	addr := netip.MustParseAddrPort("127.0.0.1:853")
	_, err := dot.NewKeepAliveExchanger(addr,
		dot.WithKeepAliveInsecure(true),
	)
	require.NoError(t, err)
}
