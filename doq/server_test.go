//go:build !acidns_no_doq

package doq_test

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
	"github.com/lestrrat-go/acidns/doq"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

func doqTestCerts(t *testing.T) (tls.Certificate, *tls.Config) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "doq-server-test"},
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
	clientCfg := &tls.Config{
		RootCAs:    pool,
		ServerName: "127.0.0.1",
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"doq"},
	}
	return cert, clientCfg
}

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
	cert, clientCfg := doqTestCerts(t)

	h := &echoHandler{}
	srv, err := doq.NewServer(
		netip.MustParseAddrPort("127.0.0.1:0"), h,
		doq.WithServerTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
	)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)
	require.NoError(t, err)

	ex, err := doq.NewClient(ctrl.Addr(),
		doq.WithTLSConfig(clientCfg),
		doq.WithServerName("127.0.0.1"),
		doq.WithPadding(false),
	)
	require.NoError(t, err)

	q, err := wire.NewMessageBuilder().
		ID(0xa1f1).
		RecursionDesired(true).
		Question(wire.NewQuestion(wire.MustParseName("a.test."), rrtype.A)).
		Build()
	require.NoError(t, err)

	qctx, qcancel := context.WithTimeout(ctx, 10*time.Second)
	defer qcancel()
	resp, err := ex.Exchange(qctx, q)
	require.NoError(t, err)
	require.True(t, resp.Flags().Response())
	require.Equal(t, 1, len(resp.Answers()))
	require.Equal(t, int32(1), h.hits.Load())
}

func TestNewServerRejectsMissingTLS(t *testing.T) {
	t.Parallel()
	_, err := doq.NewServer(netip.MustParseAddrPort("127.0.0.1:0"), &echoHandler{})
	require.ErrorIs(t, err, doq.ErrTLSConfigRequired)
}

func TestNewServerRejectsNilHandler(t *testing.T) {
	t.Parallel()
	cert, _ := doqTestCerts(t)
	_, err := doq.NewServer(
		netip.MustParseAddrPort("127.0.0.1:0"), nil,
		doq.WithServerTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
	)
	require.ErrorIs(t, err, doq.ErrNilHandler)
}

func TestServerLifecycle(t *testing.T) {
	t.Parallel()
	cert, _ := doqTestCerts(t)
	srv, err := doq.NewServer(
		netip.MustParseAddrPort("127.0.0.1:0"), &echoHandler{},
		doq.WithServerTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	ctrl, err := srv.Run(ctx)
	require.NoError(t, err)
	cancel()

	select {
	case <-ctrl.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("Done did not fire after ctx cancellation")
	}
	if err := ctrl.Err(); err != nil && !errors.Is(err, doq.ErrServerClosed) {
		t.Fatalf("unexpected terminal error: %v", err)
	}
}

func TestDoQSentinelErrors(t *testing.T) {
	t.Parallel()
	_, err := doq.NewServer(netip.MustParseAddrPort("127.0.0.1:0"), nil)
	require.ErrorIs(t, err, doq.ErrNilHandler)
	_, err = doq.NewServer(netip.MustParseAddrPort("127.0.0.1:0"), &echoHandler{})
	require.ErrorIs(t, err, doq.ErrTLSConfigRequired)
}
