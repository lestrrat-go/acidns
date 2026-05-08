package examples_test

import (
	"fmt"
	"strings"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/zonefile"
)

func Example_dnszone_parse() {
	// Parse reads RFC 1035 §5 master-file format. Pass any io.Reader.
	src := strings.NewReader(`$ORIGIN example.com.
$TTL 60
@   IN  SOA  ns1.example.com. hm.example.com. ( 1 7200 3600 1209600 60 )
@   IN  NS   ns1.example.com.
ns1 IN  A    192.0.2.10
www IN  A    192.0.2.42
`)

	z, err := zonefile.Parse(src)
	if err != nil {
		fmt.Println("parse:", err)
		return
	}
	fmt.Println("origin:", z.Origin())

	// Walk the parsed records and find the SOA serial.
	for _, rec := range z.Records() {
		if soa, ok := wire.RDataAs[rdata.SOA](rec); ok {
			fmt.Println("soa serial:", soa.Serial())
			break
		}
	}

	// OUTPUT:
	// origin: example.com.
	// soa serial: 1
}
