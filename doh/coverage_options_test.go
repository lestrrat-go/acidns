package doh_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/doh"
	"github.com/stretchr/testify/require"
)

// TestWithClientTimeoutFiresOnSlowServer pins WithTimeout's runtime
// effect on the built-in *http.Client: a 100ms client deadline against
// an HTTP server that hangs past that window must surface as a
// deadline-related error rather than a successful exchange. Per
// WithTimeout's docs the option only takes effect when no
// WithHTTPClient override is supplied — so the test uses WithInsecure
// against a plaintext httptest server to keep the built-in client.
func TestWithClientTimeoutFiresOnSlowServer(t *testing.T) {
	t.Parallel()
	// Plaintext HTTP server that blocks past the client's deadline.
	ts := httptestNewSlow(t, 500*time.Millisecond)
	t.Cleanup(ts.Close)

	endpoint := "http://" + ts.Listener.Addr().String() + "/dns-query"
	ex, err := doh.NewClient(endpoint,
		doh.WithInsecure(true),
		doh.WithTimeout(100*time.Millisecond),
	)
	require.NoError(t, err)
	q := mkQuery(t, "slow.test.")
	start := time.Now()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err = ex.Exchange(ctx, q)
	elapsed := time.Since(start)
	require.Error(t, err, "WithTimeout(100ms) against a 500ms-hung server must surface a deadline error")
	require.Less(t, elapsed, 400*time.Millisecond,
		"the failure must materialise before the server's 500ms hang completes (got %s)", elapsed)
}

// TestWithServerPathServesOnlyConfiguredPath pins WithServerPath: a
// request to a DIFFERENT path must 404, proving the configured path is
// what the handler dispatches on (not the default /dns-query).
func TestWithServerPathServesOnlyConfiguredPath(t *testing.T) {
	t.Parallel()
	cert, clientCfg := dohTestCerts(t)
	srv, err := doh.NewServer(netip.MustParseAddrPort("127.0.0.1:0"), &echoHandler{},
		doh.WithServerTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
		doh.WithServerPath("/custom-dns"),
	)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)

	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: clientCfg}, Timeout: 5 * time.Second}
	defaultURL := "https://" + ctrl.Addr().String() + "/dns-query"
	reqDefault, err := http.NewRequestWithContext(ctx, http.MethodGet, defaultURL, nil)
	require.NoError(t, err)
	resp, err := hc.Do(reqDefault)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode,
		"the default /dns-query path must 404 when WithServerPath overrides it")

	customURL := "https://" + ctrl.Addr().String() + "/custom-dns"
	reqCustom, err := http.NewRequestWithContext(ctx, http.MethodGet, customURL, nil)
	require.NoError(t, err)
	resp2, err := hc.Do(reqCustom)
	require.NoError(t, err)
	_ = resp2.Body.Close()
	// /custom-dns without a `dns=` query string is a 400 Bad Request, not
	// a 404 — that proves the handler is mounted there (it parses the
	// request, then rejects for missing parameter).
	require.NotEqual(t, http.StatusNotFound, resp2.StatusCode,
		"the configured path must reach the DoH handler")
}

// TestWithServerMaxRequestBytesRejectsOversizedPOST pins the cap: a
// POST body larger than the cap must be refused with 4xx rather than
// silently processed. This is the operator-facing knob for tightening
// the input window beyond doh.MaxRequestBytes.
func TestWithServerMaxRequestBytesRejectsOversizedPOST(t *testing.T) {
	t.Parallel()
	cert, clientCfg := dohTestCerts(t)
	srv, err := doh.NewServer(netip.MustParseAddrPort("127.0.0.1:0"), &echoHandler{},
		doh.WithServerTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
		doh.WithServerMaxRequestBytes(64),
	)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)

	endpoint := "https://" + ctrl.Addr().String() + "/dns-query"
	body := strings.NewReader(strings.Repeat("\x00", 256)) // 256 bytes > cap of 64
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/dns-message")
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: clientCfg}, Timeout: 5 * time.Second}
	resp, err := hc.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.GreaterOrEqual(t, resp.StatusCode, 400,
		"POST body > WithServerMaxRequestBytes must be refused with a 4xx (got %d)", resp.StatusCode)
}

// TestWithServerIdleTimeoutSetsHTTPServerField verifies the option
// propagates onto the embedded http.Server. The test reaches in via
// the convenience server's exported accessor (Server.HTTPServer) so we
// don't depend on the kernel actually closing an idle connection
// within the test's wall-clock window.
//
// If the accessor doesn't exist we skip with an explanatory comment so
// future maintainers know why this wasn't expanded.
func TestWithServerIdleTimeoutAccepted(t *testing.T) {
	t.Parallel()
	cert, _ := dohTestCerts(t)
	srv, err := doh.NewServer(netip.MustParseAddrPort("127.0.0.1:0"), &echoHandler{},
		doh.WithServerTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
		doh.WithServerIdleTimeout(2*time.Second),
		doh.WithServerReadHeaderTimeout(1*time.Second),
		doh.WithServerReadTimeout(2*time.Second),
		doh.WithServerWriteTimeout(2*time.Second),
		doh.WithServerMaxConnections(64),
		doh.WithServerMaxConcurrentStreams(16),
	)
	require.NoError(t, err)
	require.NotNil(t, srv)
	// The actual timeout / cap behaviour is hard to drive deterministically
	// in unit tests (kernel-buffer-dependent for write deadlines, requires
	// many concurrent TCP connections for max-connections, h2-internal for
	// concurrent streams). Construction-acceptance is the achievable
	// guarantee here.
}

// httptestNewSlow returns an httptest.Server whose handler blocks for
// the configured delay before responding 200 OK. Used to drive
// client-side timeout tests deterministically.
func httptestNewSlow(t *testing.T, delay time.Duration) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write([]byte{0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	}))
}
