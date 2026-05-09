package examples_test

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/lestrrat-go/acidns/mdns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
)

func Example_mdns_parse() {
	// ParseBrowseResponse extracts service entries from an mDNS response —
	// useful when you've captured a packet outside the built-in Browse
	// helper, or want unit-test coverage without touching the network.
	svcType := wire.MustParseName("_http._tcp.local")
	instance := wire.MustParseName("My Printer._http._tcp.local")
	host := wire.MustParseName("printer.local")

	txt, _ := rdata.NewTXT("path=/admin", "model=acidns")
	resp, _ := wire.NewBuilder().
		ID(0).
		Response(true).
		Answer(wire.NewRecord(svcType, time.Minute, rdata.NewPTR(instance))).
		Answer(wire.NewRecord(instance, time.Minute, rdata.NewSRV(0, 0, 80, host))).
		Answer(wire.NewRecord(instance, time.Minute, txt)).
		Additional(wire.NewRecord(host, time.Minute, rdata.MustNewA(netip.MustParseAddr("192.0.2.50")))).
		Build()

	for _, s := range mdns.ParseBrowseResponse(resp) {
		fmt.Println("instance:", s.Instance)
		fmt.Println("host:", s.Host, "port:", s.Port)
		fmt.Println("addrs:", s.Addrs)
		fmt.Println("path:", s.Text["path"])
	}

	// OUTPUT:
	// instance: my printer
	// host: printer.local. port: 80
	// addrs: [192.0.2.50]
	// path: /admin
}
