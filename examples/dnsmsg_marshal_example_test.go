package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

func Example_dnsmsg_marshal() {
	// Marshal serialises a Message to msg-format bytes; Unmarshal is the
	// inverse. The pair is what every transport (UDP, TCP, DoT, DoH, DoQ)
	// hands to the network.
	original, _ := wire.NewMessageBuilder().
		ID(0xabcd).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()

	msg, err := wire.Marshal(original)
	if err != nil {
		fmt.Println("marshal:", err)
		return
	}

	parsed, err := wire.Unmarshal(msg)
	if err != nil {
		fmt.Println("unmarshal:", err)
		return
	}

	fmt.Printf("msg bytes: %d\n", len(msg))
	fmt.Printf("parsed id=%#x type=%s\n", parsed.ID(), parsed.Questions()[0].Type())

	// OUTPUT:
	// msg bytes: 29
	// parsed id=0xabcd type=A
}
