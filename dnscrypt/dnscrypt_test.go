package dnscrypt_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/lestrrat-go/acidns/dnscrypt"
	"github.com/stretchr/testify/require"
)

type testCert struct {
	cert        *dnscrypt.Cert
	providerPub ed25519.PublicKey
	resolverPK  [32]byte
	resolverSK  [32]byte
}

func makeCert(t *testing.T) testCert {
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

	cert := &dnscrypt.Cert{
		ESVersion:     dnscrypt.ESVersion2,
		ProtocolMinor: 0,
		ResolverPK:    resolverPK,
		ClientMagic:   [8]byte{'a', 'c', 'i', 'd', 'n', 's', 'c', 't'},
		Serial:        1,
		ValidFrom:     time.Now().Add(-time.Hour).UTC().Truncate(time.Second),
		ValidUntil:    time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second),
	}
	dnscrypt.SignCert(cert, providerPriv)
	return testCert{cert: cert, providerPub: providerPub, resolverPK: resolverPK, resolverSK: resolverSK}
}

func TestCertEncodeDecodeVerify(t *testing.T) {
	t.Parallel()

	tc := makeCert(t)

	wire := dnscrypt.EncodeCert(tc.cert)
	require.Equal(t, 124, len(wire))

	parsed, err := dnscrypt.ParseCert(wire)
	require.NoError(t, err)
	require.NoError(t, parsed.Verify(tc.providerPub, time.Now()))
}

func TestCertVerifyExpired(t *testing.T) {
	t.Parallel()
	tc := makeCert(t)
	err := tc.cert.Verify(tc.providerPub, time.Now().Add(48*time.Hour))
	require.ErrorIs(t, err, dnscrypt.ErrCertExpired)
}

func TestCertVerifyTampered(t *testing.T) {
	t.Parallel()
	tc := makeCert(t)
	tc.cert.Serial = 999 // not part of original signed data
	err := tc.cert.Verify(tc.providerPub, time.Now())
	require.ErrorIs(t, err, dnscrypt.ErrCertSignatureInvalid)
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	t.Parallel()

	tc := makeCert(t)
	cert, resolverSK := tc.cert, tc.resolverSK

	// Client side keys.
	var clientSK [32]byte
	_, err := rand.Read(clientSK[:])
	require.NoError(t, err)
	cpk, err := curve25519.X25519(clientSK[:], curve25519.Basepoint)
	require.NoError(t, err)
	var clientPK [32]byte
	copy(clientPK[:], cpk)

	var nonce [12]byte
	_, err = rand.Read(nonce[:])
	require.NoError(t, err)

	plaintext := []byte("hello dnscrypt")
	ct, err := dnscrypt.Encrypt(cert, clientPK, clientSK, nonce, plaintext)
	require.NoError(t, err)

	// Resolver-side decrypt + re-encrypt as a response.
	resp, err := simulateResolver(t, cert, resolverSK, ct)
	require.NoError(t, err)

	got, err := dnscrypt.Decrypt(cert, clientSK, nonce, resp)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)
}

// simulateResolver decrypts the client's query, echoes the plaintext
// back as a DNSCrypt response, and returns the wire bytes.
func simulateResolver(t *testing.T, cert *dnscrypt.Cert, resolverSK [32]byte, query []byte) ([]byte, error) {
	t.Helper()
	require.Equal(t, cert.ClientMagic[:], query[:8])

	var clientPK [32]byte
	copy(clientPK[:], query[8:40])
	var clientNonce [12]byte
	copy(clientNonce[:], query[40:52])

	// Resolver-side decrypt: shared key from resolverSK + clientPK.
	shared, err := curve25519.X25519(resolverSK[:], clientPK[:])
	require.NoError(t, err)
	require.Equal(t, 32, len(shared))

	plaintext, err := decryptHelper(shared, clientNonce, query[52:])
	require.NoError(t, err)

	// Resolver responds with the same plaintext (bypassing actual DNS).
	var serverNonce [12]byte
	_, err = rand.Read(serverNonce[:])
	require.NoError(t, err)

	respCT, err := encryptHelper(shared, clientNonce, serverNonce, plaintext)
	require.NoError(t, err)

	out := make([]byte, 0, 32+len(respCT))
	out = append(out, []byte("r6fnvWj8")...)
	out = append(out, clientNonce[:]...)
	out = append(out, serverNonce[:]...)
	out = append(out, respCT...)
	return out, nil
}
