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

	"github.com/lestrrat-go/acidns/dot"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

func Example_dot_exchange() {
	// Bring up a self-signed TLS listener on 127.0.0.1, dial it with
	// dot.New, and exchange a single A query. The server returns a
	// fixed answer so the example output is deterministic.
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

	srvCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
	if err != nil {
		fmt.Println("listen:", err)
		return
	}
	defer func() { _ = ln.Close() }()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				var hdr [2]byte
				if _, err := io.ReadFull(c, hdr[:]); err != nil {
					return
				}
				body := make([]byte, binary.BigEndian.Uint16(hdr[:]))
				if _, err := io.ReadFull(c, body); err != nil {
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
						rdata.MustNewA(netip.MustParseAddr("198.51.100.42")))).
					Build()
				out, _ := wire.Marshal(resp)
				binary.BigEndian.PutUint16(hdr[:], uint16(len(out)))
				_, _ = c.Write(hdr[:])
				_, _ = c.Write(out)
			}(conn)
		}
	}()

	a := ln.Addr().(*net.TCPAddr)
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port))
	clientCfg := &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}

	ex, err := dot.New(addr, dot.WithTLSConfig(clientCfg), dot.WithServerName("127.0.0.1"))
	if err != nil {
		fmt.Println("dot:", err)
		return
	}

	q, _ := wire.NewMessageBuilder().
		ID(0xaa55).RecursionDesired(true).
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
		fmt.Println("dot answer:", a.Addr())
	}

	// OUTPUT:
	// dot answer: 198.51.100.42
}
