package examples_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/lestrrat-go/acidns/sig0"
)

func Example_sig0_sign_verify() {
	// SIG(0) (RFC 2931) signs a DNS message with a private key whose public
	// counterpart lives in DNS as a KEY/DNSKEY RR. Unlike TSIG, no shared
	// secret is needed.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("keygen:", err)
		return
	}

	q, _ := dnsmsg.NewBuilder().
		ID(0xdead).
		Question(dnsmsg.NewQuestion(dnsname.MustParse("example.com"), rrtype.A)).
		Build()
	wire, err := dnsmsg.Marshal(q)
	if err != nil {
		fmt.Println("marshal:", err)
		return
	}

	signer := dnsname.MustParse("test.signer")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	signed, err := sig0.Sign(wire, signer, rdata.AlgED25519, 4242,
		func(payload []byte) ([]byte, error) {
			return ed25519.Sign(priv, payload), nil
		}, now, time.Hour)
	if err != nil {
		fmt.Println("sign:", err)
		return
	}

	body, err := sig0.Verify(signed, rdata.AlgED25519, pub, signer, now)
	if err != nil {
		fmt.Println("verify:", err)
		return
	}

	verified, _ := dnsmsg.Unmarshal(body)
	fmt.Printf("verified id: %#x\n", verified.ID())

	// OUTPUT:
	// verified id: 0xdead
}
