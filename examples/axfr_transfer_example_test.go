package examples_test

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/authoritative"
	"github.com/lestrrat-go/acidns/axfr"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/zonefile"
)

func Example_axfr_transfer() {
	// Bring up an authoritative server over TCP — AXFR mandates a stream
	// transport (RFC 5936). The same server can answer normal queries too.
	z, _ := zonefile.Parse(strings.NewReader(`$ORIGIN example.com.
$TTL 60
@   IN  SOA  ns1.example.com. hm.example.com. ( 1 7200 3600 1209600 60 )
@   IN  NS   ns1.example.com.
ns1 IN  A    192.0.2.10
www IN  A    192.0.2.42
`))
	// Zone transfers are refused by default; install a policy that admits
	// the request (production callers should match w.RemoteAddr() against
	// an allow-list of secondaries or verify a TSIG MAC).
	h, err := authoritative.New(
		authoritative.WithZone(z),
		authoritative.WithAXFRPolicy(func(_ context.Context, _ acidns.ResponseWriter, _ wire.Message) bool { return true }),
	)
	if err != nil {
		fmt.Println("auth:", err)
		return
	}
	srv, err := acidns.NewTCPServer(netip.MustParseAddrPort("127.0.0.1:0"), h)
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

	// Client side: open a TCP stream-exchanger and pull records.
	tx, err := acidns.NewTCPClient(ctrl.Addr())
	if err != nil {
		fmt.Println("dial:", err)
		return
	}
	xferCtx, xcancel := context.WithTimeout(ctx, 5*time.Second)
	defer xcancel()
	xfer, err := axfr.Start(xferCtx, tx, wire.MustParseName("example.com"))
	if err != nil {
		fmt.Println("axfr start:", err)
		return
	}
	defer func() { _ = xfer.Close() }()

	var soaCount, aCount int
	for {
		ev, err := xfer.Next(xferCtx)
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Println("next:", err)
			return
		}
		switch ev.Record().Type() {
		case rrtype.SOA:
			soaCount++
		case rrtype.A:
			aCount++
		}
	}
	fmt.Println("leading+trailing SOA:", soaCount)
	fmt.Println("A records:", aCount)

	// OUTPUT:
	// leading+trailing SOA: 2
	// A records: 2
}
