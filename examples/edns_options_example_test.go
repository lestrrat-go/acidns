package examples_test

import (
	"fmt"
	"net/netip"

	"github.com/lestrrat-go/acidns/dnsmsg"
)

func Example_edns_options() {
	// Build an OPT pseudo-RR with several EDNS options. Each helper has
	// a typed constructor and a typed parser.
	cookie := dnsmsg.NewClientCookie([8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
	ecs, err := dnsmsg.NewClientSubnet(netip.MustParsePrefix("192.0.2.0/24"), 0)
	if err != nil {
		fmt.Println("ecs:", err)
		return
	}
	ede := dnsmsg.NewExtendedError(dnsmsg.ExtendedErrorDNSSECBogus, "RRSIG expired")

	opt := dnsmsg.NewEDNSBuilder().
		UDPSize(1232).
		DO(true).
		Option(cookie).
		Option(ecs).
		Option(ede).
		Build()

	fmt.Println("DO:", opt.DO())
	fmt.Println("UDP size:", opt.UDPSize())
	for _, o := range opt.Options() {
		switch o.Code() {
		case dnsmsg.EDNSOptionCookie:
			fmt.Println("cookie option present")
		case dnsmsg.EDNSOptionClientSubnet:
			pfx, scope, _ := dnsmsg.ClientSubnet(o)
			fmt.Println("client-subnet:", pfx, "scope:", scope)
		case dnsmsg.EDNSOptionExtendedDNS:
			code, text, _ := dnsmsg.ExtendedError(o)
			fmt.Println("ede:", code, text)
		}
	}

	// OUTPUT:
	// DO: true
	// UDP size: 1232
	// cookie option present
	// client-subnet: 192.0.2.0/24 scope: 0
	// ede: 6 RRSIG expired
}
