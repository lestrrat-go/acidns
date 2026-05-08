package dnscrypt_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"

	"github.com/lestrrat-go/acidns/dnscrypt"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// TestParseCertErrors covers the early-return branches of ParseCert.
func TestParseCertErrors(t *testing.T) {
	t.Parallel()

	t.Run("too short", func(t *testing.T) {
		_, err := dnscrypt.ParseCert(make([]byte, 50))
		require.Error(t, err)
		require.Contains(t, err.Error(), "too short")
	})

	t.Run("wrong magic", func(t *testing.T) {
		buf := make([]byte, 124)
		copy(buf[0:4], []byte("XXXX"))
		_, err := dnscrypt.ParseCert(buf)
		require.ErrorIs(t, err, dnscrypt.ErrCertMagicMismatch)
	})
}

// TestCertVerifyUnsupportedESVersion exercises the ES-version branch of Verify.
func TestCertVerifyUnsupportedESVersion(t *testing.T) {
	t.Parallel()

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
		ESVersion:   dnscrypt.ESVersion1, // unsupported
		ResolverPK:  resolverPK,
		ClientMagic: [8]byte{'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'},
		Serial:      1,
		ValidFrom:   time.Now().Add(-time.Hour).UTC().Truncate(time.Second),
		ValidUntil:  time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second),
	}
	dnscrypt.SignCert(cert, providerPriv)

	err = cert.Verify(providerPub, time.Now())
	require.ErrorIs(t, err, dnscrypt.ErrUnsupportedESVersion)
}

// TestEncryptUnsupportedESVersion covers the early-return guard in Encrypt.
func TestEncryptUnsupportedESVersion(t *testing.T) {
	t.Parallel()
	cert := &dnscrypt.Cert{ESVersion: dnscrypt.ESVersion1}
	_, err := dnscrypt.Encrypt(cert, [32]byte{}, [32]byte{}, [12]byte{}, []byte("x"))
	require.ErrorIs(t, err, dnscrypt.ErrUnsupportedESVersion)
}

// TestDecryptErrors covers Decrypt's guard clauses and AEAD failure.
func TestDecryptErrors(t *testing.T) {
	t.Parallel()

	cert, _, _, _ := makeCert(t)

	t.Run("unsupported ES version", func(t *testing.T) {
		bad := *cert
		bad.ESVersion = dnscrypt.ESVersion1
		_, err := dnscrypt.Decrypt(&bad, [32]byte{}, [12]byte{}, make([]byte, 64))
		require.ErrorIs(t, err, dnscrypt.ErrUnsupportedESVersion)
	})

	t.Run("packet too short", func(t *testing.T) {
		_, err := dnscrypt.Decrypt(cert, [32]byte{}, [12]byte{}, make([]byte, 4))
		require.ErrorIs(t, err, dnscrypt.ErrPlainTextTooShort)
	})

	t.Run("bad resolver magic", func(t *testing.T) {
		buf := make([]byte, 64)
		copy(buf[0:8], []byte("ZZZZZZZZ"))
		_, err := dnscrypt.Decrypt(cert, [32]byte{}, [12]byte{}, buf)
		require.ErrorIs(t, err, dnscrypt.ErrResponseMagic)
	})

	t.Run("client nonce mismatch", func(t *testing.T) {
		buf := make([]byte, 64)
		copy(buf[0:8], []byte("r6fnvWj8"))
		// bytes [8:20] are zero — caller passes a different nonce.
		var clientNonce [12]byte
		clientNonce[0] = 0xAA
		_, err := dnscrypt.Decrypt(cert, [32]byte{}, clientNonce, buf)
		require.Error(t, err)
		require.Contains(t, err.Error(), "client nonce mismatch")
	})

	t.Run("aead open failure", func(t *testing.T) {
		// Build a packet with valid magic and matching client nonce but
		// garbage ciphertext so chacha20poly1305.Open fails.
		var clientNonce [12]byte
		_, err := rand.Read(clientNonce[:])
		require.NoError(t, err)

		var clientSK [32]byte
		_, err = rand.Read(clientSK[:])
		require.NoError(t, err)

		buf := make([]byte, 0, 96)
		buf = append(buf, []byte("r6fnvWj8")...)
		buf = append(buf, clientNonce[:]...)
		buf = append(buf, make([]byte, 12)...) // server nonce
		buf = append(buf, make([]byte, 64)...) // bogus ciphertext
		_, err = dnscrypt.Decrypt(cert, clientSK, clientNonce, buf)
		require.Error(t, err)
		require.Contains(t, err.Error(), "decrypt")
	})
}

// TestUnpadErrorsViaDecrypt drives the bad-padding paths of unpad through
// the public Decrypt API by crafting a payload whose plaintext we control.
func TestUnpadErrorsViaDecrypt(t *testing.T) {
	t.Parallel()

	cert, _, _, resolverSK := makeCert(t)

	// We need a valid encrypted payload whose plaintext lacks the 0x80
	// sentinel. Easiest: bypass dnscrypt.Encrypt's pad() by encrypting
	// directly with the shared key.
	var clientSK [32]byte
	_, err := rand.Read(clientSK[:])
	require.NoError(t, err)
	clientPKBytes, err := curve25519.X25519(clientSK[:], curve25519.Basepoint)
	require.NoError(t, err)

	shared, err := curve25519.X25519(resolverSK[:], clientPKBytes)
	require.NoError(t, err)

	var clientNonce [12]byte
	_, err = rand.Read(clientNonce[:])
	require.NoError(t, err)
	var serverNonce [12]byte
	_, err = rand.Read(serverNonce[:])
	require.NoError(t, err)

	buildPacket := func(plain []byte) []byte {
		ct, err := encryptHelperRaw(shared, clientNonce, serverNonce, plain)
		require.NoError(t, err)
		out := make([]byte, 0, 32+len(ct))
		out = append(out, []byte("r6fnvWj8")...)
		out = append(out, clientNonce[:]...)
		out = append(out, serverNonce[:]...)
		out = append(out, ct...)
		return out
	}

	t.Run("bad padding byte", func(t *testing.T) {
		// Plaintext ends in something that's neither 0x00 nor 0x80.
		pkt := buildPacket([]byte{0x01, 0x02, 0x42})
		_, err := dnscrypt.Decrypt(cert, clientSK, clientNonce, pkt)
		require.Error(t, err)
		require.Contains(t, err.Error(), "bad padding")
	})

	t.Run("missing sentinel - all zero", func(t *testing.T) {
		// Plaintext is all 0x00 → unpad walks through every byte and
		// returns "padding sentinel not found".
		pkt := buildPacket(make([]byte, 8))
		_, err := dnscrypt.Decrypt(cert, clientSK, clientNonce, pkt)
		require.Error(t, err)
		require.Contains(t, err.Error(), "padding sentinel not found")
	})
}

// encryptHelperRaw seals plaintext as-is (no DNSCrypt padding) so the test
// can craft malformed payloads. Mirrors encryptHelper but skips pad().
func encryptHelperRaw(sharedKey []byte, clientNonce, serverNonce [12]byte, plain []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(sharedKey)
	if err != nil {
		return nil, err
	}
	var nonce [24]byte
	copy(nonce[:12], clientNonce[:])
	copy(nonce[12:], serverNonce[:])
	return aead.Seal(nil, nonce[:], plain, nil), nil
}

// TestNewUnsupportedESVersion exercises New's guard clause.
func TestNewUnsupportedESVersion(t *testing.T) {
	t.Parallel()
	cert := &dnscrypt.Cert{ESVersion: dnscrypt.ESVersion1}
	_, err := dnscrypt.New(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 53), cert)
	require.ErrorIs(t, err, dnscrypt.ErrUnsupportedESVersion)
}

// TestNewWithTimeoutOption exercises the option-applying code path and the
// fallback timeout branch in Exchange (when ctx has no deadline).
func TestNewWithTimeoutOption(t *testing.T) {
	t.Parallel()

	cert, _, _, resolverSK := makeCert(t)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })

	go func() {
		buf := make([]byte, 4096)
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		respPkt, err := buildFakeResponse(buf[:n], cert, resolverSK)
		if err != nil {
			return
		}
		_, _ = pc.WriteTo(respPkt, src)
	}()

	a := pc.LocalAddr().(*net.UDPAddr)
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port))
	ex, err := dnscrypt.New(addr, cert, dnscrypt.WithTimeout(3*time.Second))
	require.NoError(t, err)

	q, _ := wire.NewBuilder().
		ID(0xbeef).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()

	// Use a context without a deadline so the e.timeout branch runs.
	resp, err := ex.Exchange(t.Context(), q)
	require.NoError(t, err)
	require.Equal(t, q.ID(), resp.ID())
}

// TestExchangeDialFailure covers the dial-error path of Exchange.
func TestExchangeDialFailure(t *testing.T) {
	t.Parallel()

	cert, _, _, _ := makeCert(t)

	// Use a routeable but unreachable address; cancel ctx immediately so
	// DialContext returns quickly with ctx.Err().
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 1)
	ex, err := dnscrypt.New(addr, cert)
	require.NoError(t, err)

	q, _ := wire.NewBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = ex.Exchange(ctx, q)
	require.ErrorIs(t, err, context.Canceled)
}

// TestExchangeReadTimeout drives the read-failure path: peer accepts the
// query but never replies before the deadline fires.
func TestExchangeReadTimeout(t *testing.T) {
	t.Parallel()

	cert, _, _, _ := makeCert(t)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	// Drain one packet but never reply.
	go func() {
		buf := make([]byte, 4096)
		_, _, _ = pc.ReadFrom(buf)
	}()

	a := pc.LocalAddr().(*net.UDPAddr)
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port))
	ex, err := dnscrypt.New(addr, cert, dnscrypt.WithTimeout(50*time.Millisecond))
	require.NoError(t, err)

	q, _ := wire.NewBuilder().
		ID(2).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()

	_, err = ex.Exchange(t.Context(), q)
	require.Error(t, err)
	require.Contains(t, err.Error(), "read")
}

// TestExchangeBadResponse covers the Decrypt-failure branch of Exchange:
// the server replies with an unrecognisable packet so Decrypt errors out.
func TestExchangeBadResponse(t *testing.T) {
	t.Parallel()

	cert, _, _, _ := makeCert(t)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })

	go func() {
		buf := make([]byte, 4096)
		_, src, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		// Reply with garbage long enough to pass the length check but
		// failing the resolver-magic comparison.
		junk := make([]byte, 64)
		copy(junk[0:8], []byte("ZZZZZZZZ"))
		_, _ = pc.WriteTo(junk, src)
	}()

	a := pc.LocalAddr().(*net.UDPAddr)
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port))
	ex, err := dnscrypt.New(addr, cert)
	require.NoError(t, err)

	q, _ := wire.NewBuilder().
		ID(3).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	_, err = ex.Exchange(ctx, q)
	require.ErrorIs(t, err, dnscrypt.ErrResponseMagic)
}

// TestExchangeUnmarshalFailure covers the wire.Unmarshal failure branch:
// server returns a successfully-decryptable packet whose plaintext is not
// a valid DNS message.
func TestExchangeUnmarshalFailure(t *testing.T) {
	t.Parallel()

	cert, _, _, resolverSK := makeCert(t)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })

	go func() {
		buf := make([]byte, 4096)
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		// Decrypt the query, then re-encrypt junk that isn't a DNS msg.
		var clientPK [32]byte
		copy(clientPK[:], buf[8:40])
		var clientNonce [12]byte
		copy(clientNonce[:], buf[40:52])
		shared, err := curve25519.X25519(resolverSK[:], clientPK[:])
		if err != nil {
			return
		}
		var serverNonce [12]byte
		_, _ = rand.Read(serverNonce[:])
		// Junk plaintext (too short to be a DNS header).
		respCT, err := encryptHelper(shared, clientNonce, serverNonce, []byte{0x01, 0x02})
		if err != nil {
			return
		}
		out := make([]byte, 0, 32+len(respCT))
		out = append(out, []byte("r6fnvWj8")...)
		out = append(out, clientNonce[:]...)
		out = append(out, serverNonce[:]...)
		out = append(out, respCT...)
		_, _ = pc.WriteTo(out, src)
		_ = n
	}()

	a := pc.LocalAddr().(*net.UDPAddr)
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port))
	ex, err := dnscrypt.New(addr, cert)
	require.NoError(t, err)

	q, _ := wire.NewBuilder().
		ID(4).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	_, err = ex.Exchange(ctx, q)
	// Server replies with junk plaintext (2 bytes) — wire.Unmarshal will
	// fail with ErrInvalidMessage. The dnscrypt layer wraps it.
	require.ErrorContains(t, err, "header too short")
}
