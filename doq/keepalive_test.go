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
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
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

// kaServer is a minimal DoQ server that accepts multiple streams per
// QUIC connection — required for testing keep-alive (the one-stream-
// per-conn scaffolding in spki_pin_test.go is too restrictive).
//
// streamCount counts every stream the server serves; connCount counts
// every QUIC connection accepted. Tests assert connCount==1 for the
// reuse case.
type kaServer struct {
	addr        netip.AddrPort
	tlsConfig   *tls.Config
	leaf        *x509.Certificate
	streamCount atomic.Int64
	connCount   atomic.Int64
}

func startKeepAliveDoQ(t *testing.T) *kaServer {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ka-test"},
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

	s := &kaServer{
		tlsConfig: clientTLS,
		leaf:      leaf,
	}
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			s.connCount.Add(1)
			go s.serveConn(conn)
		}
	}()

	a := udpConn.LocalAddr().(*net.UDPAddr)
	s.addr = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port))
	return s
}

func (s *kaServer) serveConn(conn *quic.Conn) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		s.streamCount.Add(1)
		go s.serveStream(stream)
	}
}

func (s *kaServer) serveStream(stream *quic.Stream) {
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
	req, err := wire.Unpack(body)
	if err != nil {
		return
	}
	ar, _ := rdata.NewA(netip.MustParseAddr("198.51.100.77"))
	resp, _ := wire.NewMessageBuilder().
		ID(req.ID()).
		Response(true).
		Question(req.Questions()[0]).
		Answer(wire.NewRecord(req.Questions()[0].Name(), time.Minute, ar)).
		Build()
	out, _ := wire.Pack(resp)
	binary.BigEndian.PutUint16(hdr[:], uint16(len(out)))
	_, _ = stream.Write(hdr[:])
	_, _ = stream.Write(out)
}

func mkKAQuery(t *testing.T, id uint16) wire.Message {
	t.Helper()
	q, err := wire.NewMessageBuilder().
		ID(id).
		RecursionDesired(true).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	require.NoError(t, err)
	return q
}

// TestKeepAliveReusesConnection asserts that two sequential Exchange
// calls on a single KeepAliveClient share one underlying QUIC
// connection — proving the cache works.
func TestKeepAliveReusesConnection(t *testing.T) {
	t.Parallel()
	srv := startKeepAliveDoQ(t)
	c, err := doq.NewKeepAliveClient(srv.addr,
		doq.WithKeepAliveTLSConfig(srv.tlsConfig),
		doq.WithKeepAliveServerName("127.0.0.1"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })

	for i := 0; i < 3; i++ {
		resp, err := c.Exchange(t.Context(), mkKAQuery(t, uint16(0x1000+i)))
		require.NoError(t, err)
		require.Equal(t, uint16(0x1000+i), resp.ID())
	}
	require.Equal(t, int64(1), srv.connCount.Load(), "all queries must share one QUIC connection")
	require.Equal(t, int64(3), srv.streamCount.Load(), "one stream per query")
}

// TestKeepAliveConcurrentExchanges drives many concurrent callers and
// asserts they all complete successfully. DoQ over QUIC supports
// per-stream concurrency, unlike DoT keep-alive which serialises.
func TestKeepAliveConcurrentExchanges(t *testing.T) {
	t.Parallel()
	srv := startKeepAliveDoQ(t)
	c, err := doq.NewKeepAliveClient(srv.addr,
		doq.WithKeepAliveTLSConfig(srv.tlsConfig),
		doq.WithKeepAliveServerName("127.0.0.1"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })

	const n = 16
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(id uint16) {
			defer wg.Done()
			resp, err := c.Exchange(t.Context(), mkKAQuery(t, id))
			if err != nil {
				errs <- err
				return
			}
			if resp.ID() != id {
				errs <- errors.New("id mismatch")
			}
		}(uint16(0x2000 + i))
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.Equal(t, int64(1), srv.connCount.Load(), "concurrent callers share one QUIC connection")
	require.GreaterOrEqual(t, srv.streamCount.Load(), int64(n))
}

func TestKeepAliveSPKIPinMatch(t *testing.T) {
	t.Parallel()
	srv := startKeepAliveDoQ(t)
	pin := spki.Hash(srv.leaf)
	c, err := doq.NewKeepAliveClient(srv.addr,
		doq.WithKeepAliveTLSConfig(srv.tlsConfig),
		doq.WithKeepAliveServerName("127.0.0.1"),
		doq.WithKeepAliveSPKIPin(pin[:]),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	resp, err := c.Exchange(t.Context(), mkKAQuery(t, 0x5151))
	require.NoError(t, err)
	require.Equal(t, uint16(0x5151), resp.ID())
}

func TestKeepAliveSPKIPinMismatch(t *testing.T) {
	t.Parallel()
	srv := startKeepAliveDoQ(t)
	wrongPin := make([]byte, spki.HashSize)
	c, err := doq.NewKeepAliveClient(srv.addr,
		doq.WithKeepAliveTLSConfig(srv.tlsConfig),
		doq.WithKeepAliveServerName("127.0.0.1"),
		doq.WithKeepAliveSPKIPin(wrongPin),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	_, err = c.Exchange(t.Context(), mkKAQuery(t, 0x5252))
	require.ErrorIs(t, err, doq.ErrSPKIPinMismatch)
}

func TestKeepAliveSPKIPinInvalidLength(t *testing.T) {
	t.Parallel()
	_, err := doq.NewKeepAliveClient(netip.MustParseAddrPort("127.0.0.1:853"),
		doq.WithKeepAliveServerName("test"),
		doq.WithKeepAliveSPKIPin(make([]byte, 16)),
	)
	require.ErrorIs(t, err, doq.ErrInvalidSPKIPin)
}

func TestKeepAliveRejectsInsecureTLSConfig(t *testing.T) {
	t.Parallel()
	tc := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "test",
		MinVersion:         tls.VersionTLS13,
	}
	_, err := doq.NewKeepAliveClient(netip.MustParseAddrPort("127.0.0.1:853"),
		doq.WithKeepAliveTLSConfig(tc),
	)
	require.ErrorIs(t, err, doq.ErrInsecureTLSConfig)
}

func TestKeepAliveAllowsInsecureWithExplicitOptIn(t *testing.T) {
	t.Parallel()
	tc := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "test",
		MinVersion:         tls.VersionTLS13,
	}
	_, err := doq.NewKeepAliveClient(netip.MustParseAddrPort("127.0.0.1:853"),
		doq.WithKeepAliveTLSConfig(tc),
		doq.WithKeepAliveInsecure(true),
	)
	require.NoError(t, err)
}

// TestKeepAliveReconnectsAfterClose: when the cached connection is
// torn down externally (here via the client's own Close), the next
// Exchange transparently dials fresh.
func TestKeepAliveReconnectsAfterClose(t *testing.T) {
	t.Parallel()
	srv := startKeepAliveDoQ(t)
	c, err := doq.NewKeepAliveClient(srv.addr,
		doq.WithKeepAliveTLSConfig(srv.tlsConfig),
		doq.WithKeepAliveServerName("127.0.0.1"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })

	_, err = c.Exchange(t.Context(), mkKAQuery(t, 0x6101))
	require.NoError(t, err)
	require.NoError(t, c.Close())

	_, err = c.Exchange(t.Context(), mkKAQuery(t, 0x6102))
	require.NoError(t, err)
	require.Equal(t, int64(2), srv.connCount.Load(), "Close must invalidate the cached conn so the next Exchange re-dials")
}

func TestKeepAliveInvalidAddress(t *testing.T) {
	t.Parallel()
	_, err := doq.NewKeepAliveClient(netip.AddrPort{})
	require.ErrorIs(t, err, doq.ErrInvalidAddress)
}

func TestKeepAliveRequiresServerName(t *testing.T) {
	t.Parallel()
	_, err := doq.NewKeepAliveClient(netip.MustParseAddrPort("127.0.0.1:853"))
	require.ErrorIs(t, err, doq.ErrServerNameRequired)
}
