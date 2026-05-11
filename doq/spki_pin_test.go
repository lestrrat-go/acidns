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
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/lestrrat-go/acidns/doq"
	"github.com/lestrrat-go/acidns/internal/spki"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// startDoQReturningCert is startDoQ plus the parsed leaf certificate
// so tests can compute the SPKI pin to assert against.
func startDoQReturningCert(t *testing.T) (netip.AddrPort, *tls.Config, *x509.Certificate) {
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

	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"doq"},
	}
	clientTLS := &tls.Config{
		RootCAs:    pool,
		ServerName: "127.0.0.1",
		MinVersion: tls.VersionTLS13,
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { _ = udpConn.Close() })

	tr := &quic.Transport{Conn: udpConn}
	t.Cleanup(func() { _ = tr.Close() })

	ln, err := tr.Listen(srvTLS, &quic.Config{MaxIdleTimeout: 30 * time.Second})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func(c *quic.Conn) {
				stream, err := c.AcceptStream(context.Background())
				if err != nil {
					return
				}
				defer func() { _ = stream.Close() }()
				var hdr [2]byte
				if _, err := io.ReadFull(stream, hdr[:]); err != nil {
					return
				}
				size := binary.BigEndian.Uint16(hdr[:])
				body := make([]byte, size)
				if _, err := io.ReadFull(stream, body); err != nil {
					return
				}
				req, err := wire.Unmarshal(body)
				if err != nil {
					return
				}
				ar, err := rdata.NewA(netip.MustParseAddr("198.51.100.77"))
				require.NoError(t, err)
				resp, _ := wire.NewMessageBuilder().
					ID(req.ID()).
					Response(true).
					Question(req.Questions()[0]).
					Answer(wire.NewRecord(req.Questions()[0].Name(), time.Minute, ar)).
					Build()
				out, _ := wire.Marshal(resp)
				binary.BigEndian.PutUint16(hdr[:], uint16(len(out)))
				_, _ = stream.Write(hdr[:])
				_, _ = stream.Write(out)
			}(conn)
		}
	}()

	a := udpConn.LocalAddr().(*net.UDPAddr)
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port)), clientTLS, leaf
}

func mkDoQQuery(t *testing.T, id uint16) wire.Message {
	t.Helper()
	q, err := wire.NewMessageBuilder().
		ID(id).
		RecursionDesired(true).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	require.NoError(t, err)
	return q
}

func TestDoQSPKIPinMatch(t *testing.T) {
	t.Parallel()
	addr, cfg, leaf := startDoQReturningCert(t)
	pin := spki.Hash(leaf)

	ex, err := doq.NewClient(addr,
		doq.WithTLSConfig(cfg),
		doq.WithServerName("127.0.0.1"),
		doq.WithSPKIPin(pin[:]),
	)
	require.NoError(t, err)

	resp, err := ex.Exchange(t.Context(), mkDoQQuery(t, 0x5151))
	require.NoError(t, err)
	require.Equal(t, uint16(0x5151), resp.ID())
}

func TestDoQSPKIPinMismatch(t *testing.T) {
	t.Parallel()
	addr, cfg, _ := startDoQReturningCert(t)

	wrongPin := make([]byte, spki.HashSize)
	ex, err := doq.NewClient(addr,
		doq.WithTLSConfig(cfg),
		doq.WithServerName("127.0.0.1"),
		doq.WithSPKIPin(wrongPin),
	)
	require.NoError(t, err)

	_, err = ex.Exchange(t.Context(), mkDoQQuery(t, 0x5252))
	require.ErrorIs(t, err, doq.ErrSPKIPinMismatch)
}

func TestDoQSPKIPinInvalidLength(t *testing.T) {
	t.Parallel()
	addr := netip.MustParseAddrPort("127.0.0.1:853")
	_, err := doq.NewClient(addr,
		doq.WithServerName("test"),
		doq.WithSPKIPin(make([]byte, 16)),
	)
	require.ErrorIs(t, err, doq.ErrInvalidSPKIPin)
}
