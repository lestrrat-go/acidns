package examples_test

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient/transport/udp"
	"github.com/lestrrat-go/acidns/dnsserver"
	"github.com/lestrrat-go/acidns/dnsserver/chaos"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

func Example_dnsserver_chaos() {
	// chaos.New responds to RFC 4892 identity queries (id.server,
	// hostname.bind, version.server, version.bind) on the CHAOS class.
	// Compose with another Handler via WithNext, or run it standalone.
	h := chaos.New(
		chaos.WithIdentifier("ns1.example.net"),
		chaos.WithVersion("acidns/dev"),
	)
	srv, err := dnsserver.ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"), h)
	if err != nil {
		fmt.Println("listen:", err)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()

	// Build a CHAOS-class TXT query for id.server.
	q, _ := wire.NewBuilder().
		ID(1).
		Question(wire.NewQuestionClass(wire.MustParseName("id.server."), rrtype.TXT, rrtype.ClassCH)).
		Build()
	ex, _ := udp.New(srv.Addr())
	qctx, qcancel := context.WithTimeout(ctx, 2*time.Second)
	defer qcancel()
	resp, err := ex.Exchange(qctx, q)
	if err != nil {
		fmt.Println("exchange:", err)
		return
	}
	txt := resp.Answers()[0].RData().(rdata.TXT)
	fmt.Println("id.server:", txt.Strings())

	// OUTPUT:
	// id.server: [ns1.example.net]
}
