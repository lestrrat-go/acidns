package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/acidns/wire"
)

func Example_dnsname_parse() {
	// Parse turns a presentation-form domain name into a wire-format Name.
	// MustParse panics on parse failure and is convenient for constants.
	n := wire.MustParseName("WWW.Example.COM")

	// Names canonicalise to lowercase wire form, so equality is
	// case-insensitive.
	fmt.Println(n.String())
	fmt.Println(n.NumLabels())
	fmt.Println(n.Equal(wire.MustParseName("www.example.com")))

	// Parent walks one label up; ok is false at the root.
	parent, ok := n.Parent()
	fmt.Println(parent.String(), ok)

	// OUTPUT:
	// www.example.com.
	// 3
	// true
	// example.com. true
}
