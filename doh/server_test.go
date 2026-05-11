package doh_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/doh"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

func dohTestCerts(t *testing.T) (tls.Certificate, *tls.Config) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "doh-server-test"},
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

func mkQuery(t *testing.T, name string) wire.Message {
	t.Helper()
	q, err := wire.NewMessageBuilder().
		ID(0xa1f1).
		RecursionDesired(true).
		Question(wire.NewQuestion(wire.MustParseName(name), rrtype.A)).
		Build()
	require.NoError(t, err)
	return q
}

// TestHandlerPostRoundTrip drives the POST path against an
// httptest.Server (plain HTTP — TLS is httptest's job).
func TestHandlerPostRoundTrip(t *testing.T) {
	t.Parallel()
	h := &echoHandler{}
	ts := httptest.NewServer(doh.NewHandler(h))
	t.Cleanup(ts.Close)

	q := mkQuery(t, "a.test.")
	body, err := wire.Marshal(q)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, ts.URL, strings.NewReader(string(body)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "application/dns-message", resp.Header.Get("Content-Type"))

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	parsed, err := wire.Unmarshal(respBody)
	require.NoError(t, err)
	require.True(t, parsed.Flags().Response())
	require.Equal(t, 1, len(parsed.Answers()))
	require.Equal(t, int32(1), h.hits.Load())
}

// TestHandlerGetRoundTrip drives the GET / base64url path.
func TestHandlerGetRoundTrip(t *testing.T) {
	t.Parallel()
	h := &echoHandler{}
	ts := httptest.NewServer(doh.NewHandler(h))
	t.Cleanup(ts.Close)

	q := mkQuery(t, "g.test.")
	body, err := wire.Marshal(q)
	require.NoError(t, err)
	dnsParam := base64.RawURLEncoding.EncodeToString(body)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+"?dns="+dnsParam, nil)
	require.NoError(t, err)
	req.Header.Set("Accept", "application/dns-message")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, int32(1), h.hits.Load())
}

func TestHandlerRejectsWrongContentType(t *testing.T) {
	t.Parallel()
	h := &echoHandler{}
	ts := httptest.NewServer(doh.NewHandler(h))
	t.Cleanup(ts.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, ts.URL, strings.NewReader("garbage"))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "text/plain")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusUnsupportedMediaType, resp.StatusCode)
}

func TestHandlerRejectsUnknownMethod(t *testing.T) {
	t.Parallel()
	h := &echoHandler{}
	ts := httptest.NewServer(doh.NewHandler(h))
	t.Cleanup(ts.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, ts.URL, strings.NewReader(""))
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

func TestHandlerNilHandlerDegradesTo500(t *testing.T) {
	t.Parallel()
	ts := httptest.NewServer(doh.NewHandler(nil))
	t.Cleanup(ts.Close)
	resp, err := http.Get(ts.URL) //nolint:noctx,bodyclose
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

// TestServerEndToEnd verifies the convenience Server wrapper works
// over actual TLS with the doh client Client.
func TestServerEndToEnd(t *testing.T) {
	t.Parallel()
	cert, clientCfg := dohTestCerts(t)
	h := &echoHandler{}
	srv, err := doh.NewServer(
		netip.MustParseAddrPort("127.0.0.1:0"), h,
		doh.WithServerTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
	)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)
	require.NoError(t, err)

	// Wait briefly for the listener to be ready.
	time.Sleep(50 * time.Millisecond)

	endpoint := "https://" + ctrl.Addr().String() + "/dns-query"
	httpClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: clientCfg},
		Timeout:   5 * time.Second,
	}
	ex, err := doh.NewClient(endpoint, doh.WithHTTPClient(httpClient))
	require.NoError(t, err)

	q := mkQuery(t, "e2e.test.")
	qctx, qcancel := context.WithTimeout(ctx, 5*time.Second)
	defer qcancel()
	resp, err := ex.Exchange(qctx, q)
	require.NoError(t, err)
	require.True(t, resp.Flags().Response())
	require.Equal(t, 1, len(resp.Answers()))
	require.Equal(t, int32(1), h.hits.Load())
}

func TestNewServerRejectsMissingTLS(t *testing.T) {
	t.Parallel()
	_, err := doh.NewServer(netip.MustParseAddrPort("127.0.0.1:0"), &echoHandler{})
	require.ErrorIs(t, err, doh.ErrTLSConfigRequired)
}

// TestServerMaxConnsPerSourceCap models a single source occupying every
// per-source slot. Once the cap is hit the server must drop additional
// connections from the same source while still admitting other sources.
// Verifies one peer can no longer starve the global slot pool.
func TestServerMaxConnsPerSourceCap(t *testing.T) {
	t.Parallel()
	cert, clientCfg := dohTestCerts(t)
	srv, err := doh.NewServer(
		netip.MustParseAddrPort("127.0.0.1:0"), &echoHandler{},
		doh.WithServerTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
		doh.WithServerMaxConnsPerSource(2),
	)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)
	require.NoError(t, err)

	// Wait briefly for the listener to be ready.
	time.Sleep(50 * time.Millisecond)

	// Open two concurrent TLS connections and complete the handshake.
	// Both occupy per-source slots for 127.0.0.1.
	dial := func() *tls.Conn {
		c, err := tls.Dial("tcp", ctrl.Addr().String(), clientCfg)
		require.NoError(t, err)
		require.NoError(t, c.Handshake())
		return c
	}
	c1 := dial()
	defer func() { _ = c1.Close() }()
	c2 := dial()
	defer func() { _ = c2.Close() }()

	// The third connection should be admitted by the kernel + the
	// limit listener but immediately closed by the server because the
	// per-source cap has been hit. Either Handshake or the first read
	// must return an error.
	c3, err := tls.Dial("tcp", ctrl.Addr().String(), clientCfg)
	if err == nil {
		_ = c3.SetDeadline(time.Now().Add(2 * time.Second))
		hsErr := c3.Handshake()
		if hsErr == nil {
			buf := make([]byte, 8)
			_, hsErr = c3.Read(buf)
		}
		_ = c3.Close()
		require.Error(t, hsErr, "third concurrent connection from same source must be dropped")
	}

	// Closing one occupant frees a slot — a new connection succeeds.
	require.NoError(t, c1.Close())
	time.Sleep(50 * time.Millisecond)
	c4, err := tls.Dial("tcp", ctrl.Addr().String(), clientCfg)
	require.NoError(t, err)
	require.NoError(t, c4.Handshake(), "slot should free after closing first conn")
	_ = c4.Close()
}

func TestDoHSentinelErrors(t *testing.T) {
	t.Parallel()
	_, err := doh.NewServer(netip.MustParseAddrPort("127.0.0.1:0"), nil)
	require.ErrorIs(t, err, doh.ErrNilHandler)
	_, err = doh.NewServer(netip.MustParseAddrPort("127.0.0.1:0"), &echoHandler{})
	require.ErrorIs(t, err, doh.ErrTLSConfigRequired)
	_, err = doh.NewClient("http://example.com/dns-query")
	require.ErrorIs(t, err, doh.ErrPlaintextRefused)
	_, err = doh.NewClient("https://invalid host/")
	require.ErrorIs(t, err, doh.ErrInvalidEndpoint)
}
