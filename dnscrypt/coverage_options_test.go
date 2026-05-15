package dnscrypt_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/dnscrypt"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/stretchr/testify/require"
)

// TestClientOptionsAccepted exercises the client-side options that have no
// other production caller in this repo: WithClock, WithClockSkew, and
// WithCertProtocolMinor. The options gate the per-Exchange validity-window
// check, so passing them through NewClient is enough to prove they are
// applied without panicking on construction.
func TestClientOptionsAccepted(t *testing.T) {
	t.Parallel()

	_, providerPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	var resolverSK [32]byte
	_, err = rand.Read(resolverSK[:])
	require.NoError(t, err)
	resolverPK, err := curve25519.X25519(resolverSK[:], curve25519.Basepoint)
	require.NoError(t, err)
	var rpk [32]byte
	copy(rpk[:], resolverPK)

	cert, err := dnscrypt.NewCert(
		dnscrypt.WithCertResolverPK(rpk),
		dnscrypt.WithCertClientMagic([8]byte{'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'}),
		dnscrypt.WithCertSerial(1),
		dnscrypt.WithCertProtocolMinor(0),
		dnscrypt.WithCertValidFrom(time.Now().Add(-time.Hour).UTC().Truncate(time.Second)),
		dnscrypt.WithCertValidUntil(time.Now().Add(24*time.Hour).UTC().Truncate(time.Second)),
	)
	require.NoError(t, err)
	dnscrypt.SignCert(cert, providerPriv)

	fixedNow := time.Now().UTC()
	addr := netip.MustParseAddrPort("127.0.0.1:65000")
	ex, err := dnscrypt.NewClient(addr,
		dnscrypt.WithCertificate(cert),
		dnscrypt.WithClockSkew(10*time.Second),
		dnscrypt.WithClock(func() time.Time { return fixedNow }),
	)
	require.NoError(t, err)
	require.NotNil(t, ex)
}

// TestServerOptionsAccepted exercises every server-side option whose only
// caller would otherwise be elsewhere in user code: BufferSize, MaxInflight,
// Clock, ClockSkew, ReplayProtection, ReplayWindow, ReplayCacheMax, and
// WriteTimeout. Passing them through NewServer proves construction accepts
// each one.
func TestServerOptionsAccepted(t *testing.T) {
	t.Parallel()

	_, providerPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	var resolverSK [32]byte
	_, err = rand.Read(resolverSK[:])
	require.NoError(t, err)
	resolverPK, err := curve25519.X25519(resolverSK[:], curve25519.Basepoint)
	require.NoError(t, err)
	var rpk [32]byte
	copy(rpk[:], resolverPK)

	cert, err := dnscrypt.NewCert(
		dnscrypt.WithCertResolverPK(rpk),
		dnscrypt.WithCertClientMagic([8]byte{1, 2, 3, 4, 5, 6, 7, 8}),
		dnscrypt.WithCertSerial(1),
		dnscrypt.WithCertValidFrom(time.Now().Add(-time.Hour).UTC().Truncate(time.Second)),
		dnscrypt.WithCertValidUntil(time.Now().Add(24*time.Hour).UTC().Truncate(time.Second)),
	)
	require.NoError(t, err)
	dnscrypt.SignCert(cert, providerPriv)

	fixedNow := time.Now().UTC()
	h := acidns.HandlerFunc(func(_ context.Context, _ acidns.ResponseWriter, _ wire.Message) {})
	srv, err := dnscrypt.NewServer(netip.MustParseAddrPort("127.0.0.1:0"), h,
		dnscrypt.WithCert(cert),
		dnscrypt.WithResolverSecretKey(resolverSK),
		dnscrypt.WithServerBufferSize(8192),
		dnscrypt.WithServerMaxInflight(64),
		dnscrypt.WithServerClock(func() time.Time { return fixedNow }),
		dnscrypt.WithServerClockSkew(15*time.Second),
		dnscrypt.WithServerReplayProtection(true),
		dnscrypt.WithServerReplayWindow(2*time.Minute),
		dnscrypt.WithServerReplayCacheMax(4096),
		dnscrypt.WithServerWriteTimeout(3*time.Second),
	)
	require.NoError(t, err)
	require.NotNil(t, srv)
}
