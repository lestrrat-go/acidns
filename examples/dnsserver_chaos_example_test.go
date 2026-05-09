package examples_test

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/chaos"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

func Example_dnsserver_chaos() {
	// chaos.New responds to RFC 4892 identity queries (id.server,
	// hostname.bind, version.server, version.bind) on the CHAOS class.
	// Compose with another Handler via WithNext, or run it standalone.
	h, err := chaos.New(
		chaos.WithIdentifier("ns1.example.net"),
		chaos.WithVersion("acidns/dev"),
	)
	if err != nil {
		fmt.Println("chaos:", err)
		return
	}
	srv, err := acidns.NewUDPServer(netip.MustParseAddrPort("127.0.0.1:0"), h)
	if err != nil {
		fmt.Println("listen:", err)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctrl, err := srv.Run(ctx)
	if err != nil {
		fmt.Println("run:", err)
		return
	}

	// Build a CHAOS-class TXT query for id.server.
	q, _ := wire.NewMessageBuilder().
		ID(1).
		Question(wire.NewQuestionClass(wire.MustParseName("id.server."), rrtype.TXT, rrtype.ClassCH)).
		Build()
	ex, _ := acidns.NewUDPExchanger(ctrl.Addr())
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
