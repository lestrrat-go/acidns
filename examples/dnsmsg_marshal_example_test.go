package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
)

func Example_dnsmsg_marshal() {
	// Marshal serialises a Message to wire-format bytes; Unmarshal is the
	// inverse. The pair is what every transport (UDP, TCP, DoT, DoH, DoQ)
	// hands to the network.
	original, _ := dnsmsg.NewBuilder().
		ID(0xabcd).
		Question(dnsmsg.NewQuestion(dnsname.MustParse("example.com"), rrtype.A)).
		Build()

	wire, err := dnsmsg.Marshal(original)
	if err != nil {
		fmt.Println("marshal:", err)
		return
	}

	parsed, err := dnsmsg.Unmarshal(wire)
	if err != nil {
		fmt.Println("unmarshal:", err)
		return
	}

	fmt.Printf("wire bytes: %d\n", len(wire))
	fmt.Printf("parsed id=%#x type=%s\n", parsed.ID(), parsed.Questions()[0].Type())

	// OUTPUT:
	// wire bytes: 29
	// parsed id=0xabcd type=A
}
