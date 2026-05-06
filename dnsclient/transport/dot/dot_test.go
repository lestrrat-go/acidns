package dot_test

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

	"github.com/lestrrat-go/acidns/dnsclient/transport/dot"
	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/stretchr/testify/require"
)

// startDoT starts a TLS-backed DNS responder on 127.0.0.1.
func startDoT(t *testing.T) (netip.AddrPort, *tls.Config) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
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
	clientCfg := &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}

	srvCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var lenBuf [2]byte
				if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
					return
				}
				n := binary.BigEndian.Uint16(lenBuf[:])
				body := make([]byte, n)
				if _, err := io.ReadFull(c, body); err != nil {
					return
				}
				req, err := dnsmsg.Unmarshal(body)
				if err != nil {
					return
				}
				resp, _ := dnsmsg.NewBuilder().
					ID(req.ID()).
					Response(true).
					Question(req.Questions()[0]).
					Answer(dnsmsg.NewRecord(req.Questions()[0].Name(), time.Minute,
						rdata.NewA(netip.MustParseAddr("198.51.100.42")))).
					Build()
				wire, _ := dnsmsg.Marshal(resp)
				binary.BigEndian.PutUint16(lenBuf[:], uint16(len(wire)))
				c.Write(lenBuf[:])
				c.Write(wire)
			}(conn)
		}
	}()

	a := ln.Addr().(*net.TCPAddr)
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port)), clientCfg
}

func TestDoTExchange(t *testing.T) {
	t.Parallel()

	addr, cfg := startDoT(t)
	ex, err := dot.New(addr, dot.WithTLSConfig(cfg), dot.WithServerName("127.0.0.1"))
	require.NoError(t, err)

	q, _ := dnsmsg.NewBuilder().
		ID(0xaa55).
		RecursionDesired(true).
		Question(dnsmsg.NewQuestion(dnsname.MustParse("example.com"), rrtype.A)).
		Build()

	resp, err := ex.Exchange(t.Context(), q)
	require.NoError(t, err)
	require.Equal(t, q.ID(), resp.ID())
	require.Equal(t, "198.51.100.42", resp.Answers()[0].RData().(rdata.A).Addr().String())
}

func TestDoTContextCancel(t *testing.T) {
	t.Parallel()

	// A non-TLS listener: TLS handshake will hang/error.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	a := ln.Addr().(*net.TCPAddr)
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port))

	ex, err := dot.New(addr, dot.WithServerName("127.0.0.1"))
	require.NoError(t, err)

	q, _ := dnsmsg.NewBuilder().
		ID(1).
		Question(dnsmsg.NewQuestion(dnsname.MustParse("example.com"), rrtype.A)).
		Build()

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	_, err = ex.Exchange(ctx, q)
	require.Error(t, err)
}
