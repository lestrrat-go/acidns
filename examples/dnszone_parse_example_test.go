package examples_test

import (
	"fmt"
	"strings"

	"github.com/lestrrat-go/acidns/dnszone"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
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

	z, err := dnszone.Parse(src)
	if err != nil {
		fmt.Println("parse:", err)
		return
	}
	fmt.Println("origin:", z.Origin())

	// Walk the parsed records and find the SOA serial.
	for _, rec := range z.Records() {
		if rec.Type() == rrtype.SOA {
			fmt.Println("soa serial:", rec.RData().(rdata.SOA).Serial())
			break
		}
	}

	// OUTPUT:
	// origin: example.com.
	// soa serial: 1
}
