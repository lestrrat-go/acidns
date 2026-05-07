package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/acidns/dnsclient/specialuse"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

func Example_specialuse_disposition() {
	// specialuse.For classifies a name per RFC 6761/7686/9476: should the
	// resolver pass it through, synthesise a loopback answer, or refuse?
	for _, n := range []string{
		"example.com",
		"localhost",
		"db.localhost",
		"any.invalid",
		"private.onion",
	} {
		fmt.Printf("%-20s %v\n", n, specialuse.For(wire.MustParseName(n)))
	}

	// LoopbackForType returns the synthetic answer for the localhost zone.
	fmt.Println("A:", specialuse.LoopbackForType(rrtype.A))
	fmt.Println("AAAA:", specialuse.LoopbackForType(rrtype.AAAA))

	// OUTPUT:
	// example.com          0
	// localhost            1
	// db.localhost         1
	// any.invalid          2
	// private.onion        2
	// A: [127.0.0.1]
	// AAAA: [::1]
}
