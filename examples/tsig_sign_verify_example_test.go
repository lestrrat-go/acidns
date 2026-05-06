package examples_test

import (
	"fmt"
	"time"

	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/lestrrat-go/acidns/tsig"
)

func Example_tsig_sign_verify() {
	// TSIG (RFC 8945) signs a marshalled DNS message in-place by appending
	// a TSIG RR to the additional section. Both sides agree on a key name,
	// algorithm, and shared secret out of band.
	key := tsig.Key{
		Name:      dnsname.MustParse("example-key"),
		Algorithm: tsig.HMACSHA256,
		Secret:    []byte("a-shared-secret-of-at-least-256-bits"),
	}

	q, _ := dnsmsg.NewBuilder().
		ID(1).
		Question(dnsmsg.NewQuestion(dnsname.MustParse("example.com"), rrtype.A)).
		Build()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	signed, err := tsig.SignMessage(q, key, now, 5*time.Minute)
	if err != nil {
		fmt.Println("sign:", err)
		return
	}

	body, _, err := tsig.Verify(signed, key, now, 5*time.Minute)
	if err != nil {
		fmt.Println("verify:", err)
		return
	}

	verified, _ := dnsmsg.Unmarshal(body)
	fmt.Println("verified id:", verified.ID())
	fmt.Println("verified question:", verified.Questions()[0].Name())

	// OUTPUT:
	// verified id: 1
	// verified question: example.com.
}
