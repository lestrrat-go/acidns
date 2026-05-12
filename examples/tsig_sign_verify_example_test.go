package examples_test

import (
	"fmt"
	"time"

	"github.com/lestrrat-go/acidns/tsig"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

func Example_tsig_sign_verify() {
	// TSIG (RFC 8945) signs a marshalled DNS message in-place by appending
	// a TSIG RR to the additional section. Both sides agree on a key name,
	// algorithm, and shared secret out of band.
	key, err := tsig.NewKey(wire.MustParseName("example-key"), tsig.HMACSHA256, []byte("a-shared-secret-of-at-least-256-bits"))
	if err != nil {
		fmt.Println("key:", err)
		return
	}

	q, _ := wire.NewMessageBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
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

	verified, _ := wire.Unpack(body)
	fmt.Println("verified id:", verified.ID())
	fmt.Println("verified question:", verified.Questions()[0].Name())

	// OUTPUT:
	// verified id: 1
	// verified question: example.com.
}
