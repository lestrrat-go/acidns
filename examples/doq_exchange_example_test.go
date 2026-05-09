//go:build !acidns_no_doq

package examples_test

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
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/lestrrat-go/acidns/doq"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

func Example_doq_exchange() {
	// Self-signed cert for 127.0.0.1; QUIC mandates ALPN "doq" and TLS 1.3.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println("genkey:", err)
		return
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		fmt.Println("cert:", err)
		return
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		fmt.Println("key:", err)
		return
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		fmt.Println("keypair:", err)
		return
	}
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
	if err != nil {
		fmt.Println("udp:", err)
		return
	}
	defer func() { _ = udpConn.Close() }()

	tr := &quic.Transport{Conn: udpConn}
	defer func() { _ = tr.Close() }()

	ln, err := tr.Listen(srvTLS, &quic.Config{MaxIdleTimeout: 30 * time.Second})
	if err != nil {
		fmt.Println("quic listen:", err)
		return
	}
	defer func() { _ = ln.Close() }()

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
				body := make([]byte, binary.BigEndian.Uint16(hdr[:]))
				if _, err := io.ReadFull(stream, body); err != nil {
					return
				}
				req, err := wire.Unmarshal(body)
				if err != nil {
					return
				}
				resp, _ := wire.NewMessageBuilder().
					ID(req.ID()).Response(true).
					Question(req.Questions()[0]).
					Answer(wire.NewRecord(req.Questions()[0].Name(), time.Minute,
						rdata.MustNewA(netip.MustParseAddr("198.51.100.77")))).
					Build()
				out, _ := wire.Marshal(resp)
				binary.BigEndian.PutUint16(hdr[:], uint16(len(out)))
				_, _ = stream.Write(hdr[:])
				_, _ = stream.Write(out)
			}(conn)
		}
	}()

	a := udpConn.LocalAddr().(*net.UDPAddr)
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port))

	ex, err := doq.New(addr, doq.WithTLSConfig(clientTLS))
	if err != nil {
		fmt.Println("doq:", err)
		return
	}

	q, _ := wire.NewMessageBuilder().
		ID(0xc0ff).RecursionDesired(true).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := ex.Exchange(ctx, q)
	if err != nil {
		fmt.Println("exchange:", err)
		return
	}
	if a, ok := wire.RDataAs[rdata.A](resp.Answers()[0]); ok {
		fmt.Println("doq answer:", a.Addr())
	}

	// OUTPUT:
	// doq answer: 198.51.100.77
}
