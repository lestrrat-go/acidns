package examples_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/netip"
	"time"

	"github.com/lestrrat-go/acidns/dnssec"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

func Example_dnssec_verify() {
	// Generate an Ed25519 keypair to drive the example. In production the
	// public key arrives in a DNSKEY RR fetched from the parent zone.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("keygen:", err)
		return
	}
	key, err := rdata.NewDNSKEY(257, 3, rdata.AlgED25519, pub)
	if err != nil {
		fmt.Println("dnskey:", err)
		return
	}

	// The RRset we'll sign.
	ar, err := rdata.NewA(netip.MustParseAddr("192.0.2.1"))
	if err != nil {
		fmt.Println("a:", err)
		return
	}
	set := []wire.Record{
		wire.NewRecord(wire.MustParseName("www.example.com"), time.Hour,
			ar),
	}

	// Build an RRSIG skeleton (no signature yet), compute the canonical
	// signed data, then sign it.
	signer := wire.MustParseName("example.com")
	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	inc := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	skel := rdata.NewRRSIG(rrtype.A, rdata.AlgED25519, 3, time.Hour,
		exp, inc, dnssec.KeyTag(key), signer, nil)
	payload, err := dnssec.SignedData(set, skel)
	if err != nil {
		fmt.Println("signdata:", err)
		return
	}
	rrsig := rdata.NewRRSIG(rrtype.A, rdata.AlgED25519, 3, time.Hour,
		exp, inc, dnssec.KeyTag(key), signer, ed25519.Sign(priv, payload))

	// Verify checks the RRSIG against the DNSKEY.
	if err := dnssec.Verify(set, rrsig, key); err != nil {
		fmt.Println("verify:", err)
		return
	}
	fmt.Println("rrsig verified")

	// OUTPUT:
	// rrsig verified
}
