package examples_test

import (
	"fmt"
	"strings"

	"github.com/lestrrat-go/acidns/resolvconf"
)

func Example_resolvconf_parse() {
	// resolvconf.Parse reads /etc/resolv.conf-style data from any io.Reader.
	// Use Load to read directly from a path on disk.
	src := strings.NewReader(`# upstream resolvers
nameserver 1.1.1.1
nameserver 8.8.8.8
search example.com
options ndots:2
`)
	cfg, err := resolvconf.Parse(src)
	if err != nil {
		fmt.Println("parse:", err)
		return
	}

	fmt.Println("nameservers:", cfg.Nameservers())
	fmt.Println("search:", cfg.Search())
	fmt.Println("ndots:", cfg.Ndots())

	// OUTPUT:
	// nameservers: [1.1.1.1:53 8.8.8.8:53]
	// search: [example.com.]
	// ndots: 2
}
