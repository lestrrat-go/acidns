package examples_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/lestrrat-go/acidns/dnssec"
	"github.com/lestrrat-go/acidns/sig0"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
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

	q, _ := wire.NewMessageBuilder().
		ID(0xdead).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	msg, err := wire.Marshal(q)
	if err != nil {
		fmt.Println("marshal:", err)
		return
	}

	signer := wire.MustParseName("test.signer")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	key := rdata.NewDNSKEY(257, 3, rdata.AlgED25519, pub)
	signed, err := sig0.Sign(msg, signer, rdata.AlgED25519, dnssec.KeyTag(key),
		func(payload []byte) ([]byte, error) {
			return ed25519.Sign(priv, payload), nil
		}, now, time.Hour)
	if err != nil {
		fmt.Println("sign:", err)
		return
	}

	body, err := sig0.Verify(signed, key, signer, now)
	if err != nil {
		fmt.Println("verify:", err)
		return
	}

	verified, _ := wire.Unmarshal(body)
	fmt.Printf("verified id: %#x\n", verified.ID())

	// OUTPUT:
	// verified id: 0xdead
}
