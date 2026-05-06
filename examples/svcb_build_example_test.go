package examples_test

import (
	"fmt"
	"net/netip"

	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsname"
)

func Example_svcb_build() {
	// Construct an HTTPS RR using the typed SvcParam helpers (RFC 9460).
	// dohpath (RFC 9461) makes the same record useful for advertising a
	// DoH endpoint.
	alpn, err := rdata.NewSvcParamALPN("h2", "h3")
	if err != nil {
		fmt.Println("alpn:", err)
		return
	}
	ipv4, err := rdata.NewSvcParamIPv4Hint(netip.MustParseAddr("192.0.2.1"))
	if err != nil {
		fmt.Println("ipv4hint:", err)
		return
	}

	rr := rdata.NewHTTPS(1, dnsname.MustParse("svc.example.com"),
		alpn,
		rdata.NewSvcParamPort(443),
		ipv4,
		rdata.NewSvcParamDOHPath("/dns-query{?dns}"),
	)

	fmt.Println("priority:", rr.Priority())
	fmt.Println("target:", rr.Target())
	fmt.Println("alpn:", rr.ALPN())
	port, _ := rr.Port()
	fmt.Println("port:", port)
	dohPath, _ := rr.DOHPath()
	fmt.Println("dohpath:", dohPath)

	// OUTPUT:
	// priority: 1
	// target: svc.example.com.
	// alpn: [h2 h3]
	// port: 443
	// dohpath: /dns-query{?dns}
}
