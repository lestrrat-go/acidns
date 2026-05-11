package dot_test

import (
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

// startDoTReturningCert is startDoT plus the parsed leaf certificate
// so tests can compute the SPKI pin to assert against.
func startDoTReturningCert(t *testing.T) (netip.AddrPort, *tls.Config, *x509.Certificate) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pin-test"},
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
				ar, err := rdata.NewA(netip.MustParseAddr("198.51.100.42"))
				require.NoError(t, err)
				resp, _ := wire.NewMessageBuilder().
					ID(req.ID()).
					Response(true).
					Question(req.Questions()[0]).
					Answer(wire.NewRecord(req.Questions()[0].Name(), time.Minute, ar)).
					Build()
				wb, _ := wire.Marshal(resp)
				binary.BigEndian.PutUint16(lenBuf[:], uint16(len(wb)))
				_, _ = c.Write(lenBuf[:])
				_, _ = c.Write(wb)
			}(conn)
		}
	}()

	a := ln.Addr().(*net.TCPAddr)
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port)), clientCfg, leaf
}

func mkDoTQuery(t *testing.T, id uint16) wire.Message {
	t.Helper()
	q, err := wire.NewMessageBuilder().
		ID(id).
		RecursionDesired(true).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	require.NoError(t, err)
	return q
}

func TestSPKIPinMatch(t *testing.T) {
	t.Parallel()
	addr, cfg, leaf := startDoTReturningCert(t)
	pin := spki.Hash(leaf)

	ex, err := dot.New(addr,
		dot.WithTLSConfig(cfg),
		dot.WithServerName("127.0.0.1"),
		dot.WithSPKIPin(pin[:]),
	)
	require.NoError(t, err)

	resp, err := ex.Exchange(t.Context(), mkDoTQuery(t, 0x1111))
	require.NoError(t, err)
	require.Equal(t, uint16(0x1111), resp.ID())
}

func TestSPKIPinMismatch(t *testing.T) {
	t.Parallel()
	addr, cfg, _ := startDoTReturningCert(t)

	wrongPin := make([]byte, spki.HashSize) // all zeros
	ex, err := dot.New(addr,
		dot.WithTLSConfig(cfg),
		dot.WithServerName("127.0.0.1"),
		dot.WithSPKIPin(wrongPin),
	)
	require.NoError(t, err)

	_, err = ex.Exchange(t.Context(), mkDoTQuery(t, 0x2222))
	require.ErrorIs(t, err, dot.ErrSPKIPinMismatch)
}

func TestSPKIPinMultiplePinsOneMatches(t *testing.T) {
	t.Parallel()
	addr, cfg, leaf := startDoTReturningCert(t)
	good := spki.Hash(leaf)
	bad := make([]byte, spki.HashSize)

	ex, err := dot.New(addr,
		dot.WithTLSConfig(cfg),
		dot.WithServerName("127.0.0.1"),
		dot.WithSPKIPin(bad),
		dot.WithSPKIPin(good[:]),
	)
	require.NoError(t, err)

	resp, err := ex.Exchange(t.Context(), mkDoTQuery(t, 0x3333))
	require.NoError(t, err)
	require.Equal(t, uint16(0x3333), resp.ID())
}

func TestSPKIPinInvalidLength(t *testing.T) {
	t.Parallel()
	addr := netip.MustParseAddrPort("127.0.0.1:853")
	_, err := dot.New(addr,
		dot.WithServerName("test"),
		dot.WithSPKIPin(make([]byte, 16)),
	)
	require.ErrorIs(t, err, dot.ErrInvalidSPKIPin)
}

func TestSPKIPinPreservesCallerVerifyConnection(t *testing.T) {
	t.Parallel()
	addr, cfg, leaf := startDoTReturningCert(t)
	pin := spki.Hash(leaf)

	// Caller-installed VerifyConnection that fails: it must run BEFORE
	// the pin check, so the handshake fails with the caller's error
	// rather than reaching the pin verifier at all.
	callerErr := io.ErrClosedPipe
	cfg = cfg.Clone()
	cfg.VerifyConnection = func(_ tls.ConnectionState) error { return callerErr }

	ex, err := dot.New(addr,
		dot.WithTLSConfig(cfg),
		dot.WithServerName("127.0.0.1"),
		dot.WithSPKIPin(pin[:]),
	)
	require.NoError(t, err)

	_, err = ex.Exchange(t.Context(), mkDoTQuery(t, 0x4444))
	require.ErrorIs(t, err, callerErr)
}
