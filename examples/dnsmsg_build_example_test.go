package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
)

func Example_dnsmsg_build() {
	// Builder constructs a Message piece-by-piece. Setters chain.
	q, err := dnsmsg.NewBuilder().
		ID(0x1234).
		RecursionDesired(true).
		Question(dnsmsg.NewQuestion(dnsname.MustParse("example.com"), rrtype.A)).
		Build()
	if err != nil {
		fmt.Println("build:", err)
		return
	}

	fmt.Printf("id=%#x rd=%t qcount=%d\n",
		q.ID(), q.Flags().RecursionDesired(), len(q.Questions()))
	fmt.Println("question:", q.Questions()[0].Name(), q.Questions()[0].Type())

	// OUTPUT:
	// id=0x1234 rd=true qcount=1
	// question: example.com. A
}
