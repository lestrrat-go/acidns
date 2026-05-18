package dot_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dot"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// TestClientWithInsecureDisablesCertVerification pins WithInsecure's
// effect: a self-signed-cert DoT server is normally rejected during
// the TLS handshake; WithInsecure(true) lets the client through.
func TestClientWithInsecureDisablesCertVerification(t *testing.T) {
	t.Parallel()
	cert, _ := dotTestCerts(t)
	srv, err := dot.NewServer(netip.MustParseAddrPort("127.0.0.1:0"), &echoHandler{},
		dot.WithServerTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
	)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)
	require.NoError(t, err)

	// Without Insecure or a CA pool the self-signed handshake fails.
	exStrict, err := dot.NewClient(ctrl.Addr(),
		dot.WithServerName("127.0.0.1"),
		// no WithInsecure, no WithTLSConfig with a pool
	)
	require.NoError(t, err)
	q, _ := wire.NewMessageBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("x.test."), rrtype.A)).
		Build()
	_, err = exStrict.Exchange(ctx, q)
	require.Error(t, err, "self-signed-cert handshake must fail without WithInsecure")

	// With Insecure, the same handshake succeeds and the query
	// completes.
	exLoose, err := dot.NewClient(ctrl.Addr(),
		dot.WithServerName("127.0.0.1"),
		dot.WithInsecure(true),
	)
	require.NoError(t, err)
	resp, err := exLoose.Exchange(ctx, q)
	require.NoError(t, err, "WithInsecure(true) must skip the self-signed-chain check")
	require.True(t, resp.Flags().Response())
}

// TestClientWithPaddingTogglesQuery exercises WithPadding by sending a
// query with padding disabled and one with padding enabled (default).
// Both must round-trip; the padding-off path is the regression-prone
// one because the option flips a wire-shape decision.
func TestClientWithPaddingTogglesQuery(t *testing.T) {
	t.Parallel()
	cert, _ := dotTestCerts(t)
	srv, err := dot.NewServer(netip.MustParseAddrPort("127.0.0.1:0"), &echoHandler{},
		dot.WithServerTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
	)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)
	require.NoError(t, err)

	for _, padding := range []bool{true, false} {
		ex, err := dot.NewClient(ctrl.Addr(),
			dot.WithServerName("127.0.0.1"),
			dot.WithInsecure(true),
			dot.WithPadding(padding),
		)
		require.NoError(t, err)
		q, _ := wire.NewMessageBuilder().
			ID(1).
			Question(wire.NewQuestion(wire.MustParseName("y.test."), rrtype.A)).
			Build()
		resp, err := ex.Exchange(ctx, q)
		require.NoError(t, err, "padding=%v exchange must succeed", padding)
		require.True(t, resp.Flags().Response())
	}
}

// TestKeepAliveOptionsRoundTrip pins the keep-alive client options
// (Timeout, Advertise) by driving a real exchange. Without these
// options the keep-alive client uses its built-in defaults; the test
// asserts the options are at least non-destructive on the happy path.
func TestKeepAliveOptionsRoundTrip(t *testing.T) {
	t.Parallel()
	cert, _ := dotTestCerts(t)
	srv, err := dot.NewServer(netip.MustParseAddrPort("127.0.0.1:0"), &echoHandler{},
		dot.WithServerTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
	)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)
	require.NoError(t, err)

	c, err := dot.NewKeepAliveClient(ctrl.Addr(),
		dot.WithKeepAliveServerName("127.0.0.1"),
		dot.WithKeepAliveInsecure(true),
		dot.WithKeepAliveTimeout(3*time.Second),
		dot.WithKeepAliveAdvertise(false),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })

	q, _ := wire.NewMessageBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("z.test."), rrtype.A)).
		Build()
	resp, err := c.Exchange(ctx, q)
	require.NoError(t, err)
	require.True(t, resp.Flags().Response())
}

// TestServerWithMaxConnsPerSourceCloses pins the per-source cap. We
// hold N connections open from one source; the (N+1)th must fail
// (kernel may queue briefly but the server closes excess connections
// promptly).
func TestServerWithMaxConnsPerSourceCloses(t *testing.T) {
	t.Parallel()
	cert, _ := dotTestCerts(t)
	const maxConns = 2
	srv, err := dot.NewServer(netip.MustParseAddrPort("127.0.0.1:0"), &echoHandler{},
		dot.WithServerTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
		dot.WithServerMaxConnsPerSource(maxConns),
	)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)
	require.NoError(t, err)

	// Open cap connections and hold them open.
	pool := x509.NewCertPool()
	_ = pool // tlsCfg below uses InsecureSkipVerify so the pool is unused here
	tlsCfg := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"dot"}, MinVersion: tls.VersionTLS13}
	conns := make([]*tls.Conn, 0, maxConns)
	t.Cleanup(func() {
		for _, c := range conns {
			_ = c.Close()
		}
	})
	for range maxConns {
		c, err := tls.Dial("tcp", ctrl.Addr().String(), tlsCfg)
		require.NoError(t, err)
		conns = append(conns, c)
	}

	// The cap+1 connection should be closed by the server (read returns
	// EOF or a reset) before we can drive a query through it.
	extra, err := tls.Dial("tcp", ctrl.Addr().String(), tlsCfg)
	if err != nil {
		// Acceptable — the server closed before the handshake completed.
		return
	}
	t.Cleanup(func() { _ = extra.Close() })
	require.NoError(t, extra.SetReadDeadline(time.Now().Add(1*time.Second)))
	buf := make([]byte, 1)
	_, err = extra.Read(buf)
	require.Error(t, err,
		"with WithServerMaxConnsPerSource(%d) the (cap+1)-th connection must be closed by the server", maxConns)
}

// TestServerOptionsRoundTrip drives a single exchange through a server
// constructed with every option whose effect is hard to assert in
// isolation (MaxConnections, MaxConnLifetime, MaxMessageSize,
// MaxQueriesPerConn, MaxInflightPerConn). Asserts the options are
// non-destructive on the happy path; their actual saturation behaviour
// would require holding many parallel connections / long-running
// queries, beyond the scope of this coverage file.
func TestServerOptionsRoundTrip(t *testing.T) {
	t.Parallel()
	cert, _ := dotTestCerts(t)
	srv, err := dot.NewServer(netip.MustParseAddrPort("127.0.0.1:0"), &echoHandler{},
		dot.WithServerTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
		dot.WithServerWriteTimeout(3*time.Second),
		dot.WithServerMaxConnections(64),
		dot.WithServerMaxMessageSize(8192),
		dot.WithServerMaxQueriesPerConn(1000),
		dot.WithServerMaxConnLifetime(15*time.Minute),
		dot.WithServerMaxInflightPerConn(16),
	)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)
	require.NoError(t, err)

	ex, err := dot.NewClient(ctrl.Addr(),
		dot.WithServerName("127.0.0.1"),
		dot.WithInsecure(true),
	)
	require.NoError(t, err)
	q, _ := wire.NewMessageBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("rt.test."), rrtype.A)).
		Build()
	resp, err := ex.Exchange(ctx, q)
	require.NoError(t, err)
	require.True(t, resp.Flags().Response())
}
