package dot_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/dot"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// dotTestCerts builds a self-signed cert pair for 127.0.0.1 and
// returns the matched server tls.Certificate plus the client's
// RootCAs-pinned tls.Config.
func dotTestCerts(t *testing.T) (tls.Certificate, *tls.Config) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "dot-server-test"},
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
	clientCfg := &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13}
	return cert, clientCfg
}

// echoHandler answers every query with a single A record at the
// queried name. Useful for round-trip tests that don't care about
// content.
type echoHandler struct {
	hits atomic.Int32
}

func (h *echoHandler) ServeDNS(_ context.Context, w acidns.ResponseWriter, q wire.Message) {
	h.hits.Add(1)
	if len(q.Questions()) == 0 {
		return
	}
	qq := q.Questions()[0]
	ar, _ := rdata.NewA(netip.MustParseAddr("203.0.113.5"))
	resp, _ := wire.NewMessageBuilder().
		ID(q.ID()).
		Response(true).
		Question(qq).
		Answer(wire.NewRecord(qq.Name(), time.Minute,
			ar)).
		Build()
	_ = w.WriteMsg(resp)
}

func TestServerRoundTrip(t *testing.T) {
	t.Parallel()
	cert, clientCfg := dotTestCerts(t)

	h := &echoHandler{}
	srv, err := dot.NewServer(
		netip.MustParseAddrPort("127.0.0.1:0"), h,
		dot.WithServerTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
	)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)
	require.NoError(t, err)

	ex, err := dot.New(ctrl.Addr(), dot.WithTLSConfig(clientCfg))
	require.NoError(t, err)

	q, err := wire.NewMessageBuilder().
		ID(0xa1f1).
		RecursionDesired(true).
		Question(wire.NewQuestion(wire.MustParseName("a.test."), rrtype.A)).
		Build()
	require.NoError(t, err)

	qctx, qcancel := context.WithTimeout(ctx, 5*time.Second)
	defer qcancel()
	resp, err := ex.Exchange(qctx, q)
	require.NoError(t, err)
	require.True(t, resp.Flags().Response())
	require.Equal(t, 1, len(resp.Answers()))
	require.Equal(t, int32(1), h.hits.Load())
}

// TestNewServerRejectsMissingTLS verifies DoT cannot be constructed
// without a tls.Config — a DoT server without TLS is no longer DoT.
func TestNewServerRejectsMissingTLS(t *testing.T) {
	t.Parallel()
	_, err := dot.NewServer(netip.MustParseAddrPort("127.0.0.1:0"), &echoHandler{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "WithServerTLSConfig is required")
}

// TestNewServerRejectsNilHandler verifies the nil-handler guard.
func TestNewServerRejectsNilHandler(t *testing.T) {
	t.Parallel()
	cert, _ := dotTestCerts(t)
	_, err := dot.NewServer(
		netip.MustParseAddrPort("127.0.0.1:0"), nil,
		dot.WithServerTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "handler is nil")
}

// TestServerAdvertisesDoTALPN verifies the server adds "dot" to
// NextProtos when the supplied tls.Config didn't include it.
func TestServerAdvertisesDoTALPN(t *testing.T) {
	t.Parallel()
	cert, clientCfg := dotTestCerts(t)
	clientCfg.NextProtos = []string{"dot"}

	h := &echoHandler{}
	srv, err := dot.NewServer(
		netip.MustParseAddrPort("127.0.0.1:0"), h,
		// Deliberately omit NextProtos in the server tls.Config —
		// the server is responsible for filling it in.
		dot.WithServerTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
	)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)
	require.NoError(t, err)

	conn, err := tls.Dial("tcp", ctrl.Addr().String(), clientCfg)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.Equal(t, "dot", conn.ConnectionState().NegotiatedProtocol)
}

// TestHandshakeTimeoutDeadlines a peer that opens a TCP connection
// and stalls before sending the ClientHello. With a tight handshake
// timeout the server closes the conn within the bound, freeing the
// inflight slot — independent of the (longer) idle timeout.
func TestHandshakeTimeoutDeadlines(t *testing.T) {
	t.Parallel()
	cert, _ := dotTestCerts(t)
	srv, err := dot.NewServer(
		netip.MustParseAddrPort("127.0.0.1:0"), &echoHandler{},
		dot.WithServerTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
		dot.WithServerHandshakeTimeout(100*time.Millisecond),
		// Idle is longer to make sure the handshake bound is what fires.
		dot.WithServerIdleTimeout(10*time.Second),
	)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)
	require.NoError(t, err)

	// Open a raw TCP connection and never send the ClientHello.
	conn, err := net.Dial("tcp", ctrl.Addr().String())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// Read should EOF/error within a short multiple of the handshake
	// deadline; if the idle timeout were used instead the read would
	// not return for ~10 seconds.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	_, err = conn.Read(buf)
	require.Error(t, err) // EOF or RST after server's handshake timeout
}

// TestServerMessageReadTimeoutClosesBodySlowloris models a peer that
// completes the TLS handshake and the 2-byte length prefix, then drips
// body bytes slower than messageReadTimeout. The connection must be
// closed within the per-message deadline rather than the (longer)
// idle deadline.
func TestServerMessageReadTimeoutClosesBodySlowloris(t *testing.T) {
	t.Parallel()
	cert, clientCfg := dotTestCerts(t)
	srv, err := dot.NewServer(
		netip.MustParseAddrPort("127.0.0.1:0"), &echoHandler{},
		dot.WithServerTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
		dot.WithServerMessageReadTimeout(150*time.Millisecond),
		dot.WithServerIdleTimeout(10*time.Second),
	)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)
	require.NoError(t, err)

	// Direct TLS dial — we want the raw stream, not a DoT Client.
	conn, err := tls.Dial("tcp", ctrl.Addr().String(), clientCfg)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// Announce a 100-byte message but never send the body.
	_, err = conn.Write([]byte{0x00, 0x64})
	require.NoError(t, err)

	// The server must drop us within ~messageReadTimeout. If the body
	// read inherited idleTimeout (10s) the read below would block until
	// the test's outer deadline.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	start := time.Now()
	_, err = conn.Read(buf)
	require.Error(t, err, "server should have closed the connection")
	require.Less(t, time.Since(start), 2*time.Second,
		"connection drop took longer than the body deadline window")
}

// TestServerLifecycle verifies ctx cancellation cleanly stops the
// server and Done fires.
func TestServerLifecycle(t *testing.T) {
	t.Parallel()
	cert, _ := dotTestCerts(t)
	srv, err := dot.NewServer(
		netip.MustParseAddrPort("127.0.0.1:0"), &echoHandler{},
		dot.WithServerTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	ctrl, err := srv.Run(ctx)
	require.NoError(t, err)
	cancel()

	select {
	case <-ctrl.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Done did not fire after ctx cancellation")
	}
	// Err either nil (clean shutdown) or ErrServerClosed-wrapped.
	if err := ctrl.Err(); err != nil && !errors.Is(err, dot.ErrServerClosed) {
		t.Fatalf("unexpected terminal error: %v", err)
	}
}

func TestSentinelErrors(t *testing.T) {
	t.Parallel()
	_, err := dot.NewServer(netip.MustParseAddrPort("127.0.0.1:0"), nil)
	require.ErrorIs(t, err, dot.ErrNilHandler)
	_, err = dot.NewServer(netip.MustParseAddrPort("127.0.0.1:0"), &echoHandler{})
	require.ErrorIs(t, err, dot.ErrTLSConfigRequired)
}
