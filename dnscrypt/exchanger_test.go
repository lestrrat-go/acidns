package dnscrypt_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/lestrrat-go/acidns/dnscrypt"
	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/stretchr/testify/require"
)

func TestExchangerEndToEnd(t *testing.T) {
	t.Parallel()

	// Generate cert + keys.
	providerPub, providerPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_ = providerPub

	var resolverSK [32]byte
	_, err = rand.Read(resolverSK[:])
	require.NoError(t, err)
	resolverPK, err := curve25519.X25519(resolverSK[:], curve25519.Basepoint)
	require.NoError(t, err)
	var rpk [32]byte
	copy(rpk[:], resolverPK)

	cert := &dnscrypt.Cert{
		ESVersion:   dnscrypt.ESVersion2,
		ResolverPK:  rpk,
		ClientMagic: [8]byte{'X', 'X', 'X', 'X', 'X', 'X', 'X', 'X'},
		Serial:      1,
		ValidFrom:   time.Now().Add(-time.Hour).UTC().Truncate(time.Second),
		ValidUntil:  time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second),
	}
	dnscrypt.SignCert(cert, providerPriv)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { pc.Close() })

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
		pc.WriteTo(respPkt, src)
	}()

	a := pc.LocalAddr().(*net.UDPAddr)
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port))
	ex, err := dnscrypt.New(addr, cert)
	require.NoError(t, err)

	q, _ := dnsmsg.NewBuilder().
		ID(0xface).
		Question(dnsmsg.NewQuestion(dnsname.MustParse("example.com"), rrtype.A)).
		Build()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	resp, err := ex.Exchange(ctx, q)
	require.NoError(t, err)
	require.Equal(t, q.ID(), resp.ID())
	require.Equal(t, 1, len(resp.Answers()))
	require.Equal(t, "203.0.113.99", resp.Answers()[0].RData().(rdata.A).Addr().String())
}

// buildFakeResponse decrypts the encrypted query, builds a DNS response
// with a fixed A record, and returns the encrypted DNSCrypt packet.
func buildFakeResponse(query []byte, cert *dnscrypt.Cert, resolverSK [32]byte) ([]byte, error) {
	var clientPK [32]byte
	copy(clientPK[:], query[8:40])
	var clientNonce [12]byte
	copy(clientNonce[:], query[40:52])

	shared, err := curve25519.X25519(resolverSK[:], clientPK[:])
	if err != nil {
		return nil, err
	}
	plain, err := decryptHelper(shared, clientNonce, query[52:])
	if err != nil {
		return nil, err
	}
	req, err := dnsmsg.Unmarshal(plain)
	if err != nil {
		return nil, err
	}
	resp, err := dnsmsg.NewBuilder().
		ID(req.ID()).
		Response(true).
		Question(req.Questions()[0]).
		Answer(dnsmsg.NewRecord(req.Questions()[0].Name(), time.Minute,
			rdata.NewA(netip.MustParseAddr("203.0.113.99")))).
		Build()
	if err != nil {
		return nil, err
	}
	respWire, err := dnsmsg.Marshal(resp)
	if err != nil {
		return nil, err
	}

	var serverNonce [12]byte
	if _, err := rand.Read(serverNonce[:]); err != nil {
		return nil, err
	}
	respCT, err := encryptHelper(shared, clientNonce, serverNonce, respWire)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 32+len(respCT))
	out = append(out, []byte("r6fnvWj8")...)
	out = append(out, clientNonce[:]...)
	out = append(out, serverNonce[:]...)
	out = append(out, respCT...)
	return out, nil
}
