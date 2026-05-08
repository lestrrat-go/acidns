package dnscrypt_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/dnscrypt"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// serverFixture bundles every key the test needs: provider Ed25519
// pair (for cert signing/verification), resolver X25519 pair
// (decrypting client queries), and the signed cert.
type serverFixture struct {
	cert        *dnscrypt.Cert
	resolverSK  [32]byte
	providerPub ed25519.PublicKey
}

func mkFixture(t *testing.T) serverFixture {
	t.Helper()
	providerPub, providerPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	var resolverSK [32]byte
	_, err = rand.Read(resolverSK[:])
	require.NoError(t, err)
	resolverPKBytes, err := curve25519.X25519(resolverSK[:], curve25519.Basepoint)
	require.NoError(t, err)
	var resolverPK [32]byte
	copy(resolverPK[:], resolverPKBytes)

	cert := dnscrypt.NewCert(
		dnscrypt.ESVersion2,
		0,
		resolverPK,
		[8]byte{'a', 'c', 'i', 'd', 'n', 's', 'c', 't'},
		1,
		time.Now().Add(-time.Hour).UTC().Truncate(time.Second),
		time.Now().Add(24*time.Hour).UTC().Truncate(time.Second),
	)
	dnscrypt.SignCert(cert, providerPriv)
	return serverFixture{cert: cert, resolverSK: resolverSK, providerPub: providerPub}
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
	resp, _ := wire.NewBuilder().
		ID(q.ID()).
		Response(true).
		Question(qq).
		Answer(wire.NewRecord(qq.Name(), time.Minute,
			rdata.NewA(netip.MustParseAddr("203.0.113.5")))).
		Build()
	_ = w.WriteMsg(resp)
}

// TestServerRoundTrip exercises a single client query against the
// server using the existing client exchanger.
func TestServerRoundTrip(t *testing.T) {
	t.Parallel()
	fx := mkFixture(t)

	h := &echoHandler{}
	srv, err := dnscrypt.NewServer(
		netip.MustParseAddrPort("127.0.0.1:0"), h,
		fx.cert, fx.resolverSK,
	)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)
	require.NoError(t, err)

	ex, err := dnscrypt.New(ctrl.Addr(), fx.cert)
	require.NoError(t, err)

	q, err := wire.NewBuilder().
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

// TestServerDropsWrongClientMagic confirms a packet whose first 8
// bytes don't match the cert's ClientMagic is silently dropped.
// Side-effect: handler hits stay at zero and the connection times
// out on the read.
func TestServerDropsWrongClientMagic(t *testing.T) {
	t.Parallel()
	fx := mkFixture(t)

	h := &echoHandler{}
	srv, err := dnscrypt.NewServer(
		netip.MustParseAddrPort("127.0.0.1:0"), h,
		fx.cert, fx.resolverSK,
	)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)
	require.NoError(t, err)

	// Build a fixture cert with a different ClientMagic; client's
	// outbound packets won't match the server's accepted prefix.
	bad := dnscrypt.NewCert(
		dnscrypt.ESVersion2, 0,
		[32]byte{}, // any
		[8]byte{'b', 'a', 'd', 'm', 'a', 'g', 'i', 'c'},
		1, time.Now().Add(-time.Hour), time.Now().Add(time.Hour),
	)
	// We don't sign it because the client doesn't verify on
	// outbound; we just need a cert object that picks the wrong
	// resolver key. Use the legitimate resolver's public key so
	// the client can complete X25519, then the server will drop
	// because ClientMagic doesn't match.
	rpk := fx.cert.ResolverPK()
	bad = dnscrypt.NewCert(
		dnscrypt.ESVersion2, 0,
		rpk,
		[8]byte{'b', 'a', 'd', 'm', 'a', 'g', 'i', 'c'},
		1, time.Now().Add(-time.Hour), time.Now().Add(time.Hour),
	)

	ex, err := dnscrypt.New(ctrl.Addr(), bad)
	require.NoError(t, err)
	q, _ := wire.NewBuilder().
		ID(1).
		RecursionDesired(true).
		Question(wire.NewQuestion(wire.MustParseName("x.test."), rrtype.A)).
		Build()
	qctx, qcancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer qcancel()
	_, err = ex.Exchange(qctx, q)
	require.Error(t, err) // read timeout — server dropped silently
	require.Equal(t, int32(0), h.hits.Load(),
		"handler must not see packets that fail ClientMagic check")
}

func TestNewServerRejectsNilHandler(t *testing.T) {
	t.Parallel()
	fx := mkFixture(t)
	_, err := dnscrypt.NewServer(
		netip.MustParseAddrPort("127.0.0.1:0"), nil,
		fx.cert, fx.resolverSK,
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "handler is nil")
}

func TestNewServerRejectsNilCert(t *testing.T) {
	t.Parallel()
	fx := mkFixture(t)
	_, err := dnscrypt.NewServer(
		netip.MustParseAddrPort("127.0.0.1:0"), &echoHandler{},
		nil, fx.resolverSK,
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "cert is nil")
}

// TestRunRejectsExpiredCert verifies Run refuses to start with a
// cert outside its validity window.
func TestRunRejectsExpiredCert(t *testing.T) {
	t.Parallel()
	fx := mkFixture(t)
	expired := dnscrypt.NewCert(
		dnscrypt.ESVersion2, 0,
		fx.cert.ResolverPK(),
		fx.cert.ClientMagic(),
		1,
		time.Now().Add(-2*time.Hour),
		time.Now().Add(-time.Hour), // already expired
	)
	srv, err := dnscrypt.NewServer(
		netip.MustParseAddrPort("127.0.0.1:0"), &echoHandler{},
		expired, fx.resolverSK,
	)
	require.NoError(t, err)
	_, err = srv.Run(t.Context())
	require.Error(t, err)
	require.ErrorIs(t, err, dnscrypt.ErrCertExpired)
}

func TestServerLifecycle(t *testing.T) {
	t.Parallel()
	fx := mkFixture(t)
	srv, err := dnscrypt.NewServer(
		netip.MustParseAddrPort("127.0.0.1:0"), &echoHandler{},
		fx.cert, fx.resolverSK,
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
	if err := ctrl.Err(); err != nil && !errors.Is(err, dnscrypt.ErrServerClosed) {
		t.Fatalf("unexpected terminal error: %v", err)
	}
}
