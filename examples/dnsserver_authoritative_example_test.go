package examples_test

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/lestrrat-go/acidns/authoritative"
	"github.com/lestrrat-go/acidns/dnsclient"
	"github.com/lestrrat-go/acidns/dnsserver"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/zonefile"
)

func Example_dnsserver_authoritative() {
	// authoritative.New + dnsserver.ListenUDP boot a serving authoritative
	// nameserver in-process. Useful for tests and toy deployments.
	z, _ := zonefile.Parse(strings.NewReader(`$ORIGIN example.com.
$TTL 60
@   IN  SOA  ns1.example.com. hm.example.com. ( 1 7200 3600 1209600 60 )
@   IN  NS   ns1.example.com.
www IN  A    192.0.2.42
`))

	h, err := authoritative.New(authoritative.WithZone(z))
	if err != nil {
		fmt.Println("authoritative:", err)
		return
	}
	srv, err := dnsserver.ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"), h)
	if err != nil {
		fmt.Println("listen:", err)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()

	// Now ask it.
	r, err := dnsclient.New(dnsclient.WithServers(srv.Addr()))
	if err != nil {
		fmt.Println("client:", err)
		return
	}
	qctx, qcancel := context.WithTimeout(ctx, 2*time.Second)
	defer qcancel()
	ans, err := r.Resolve(qctx, wire.MustParseName("www.example.com"), rrtype.A)
	if err != nil {
		fmt.Println("resolve:", err)
		return
	}
	for _, rec := range ans.Records() {
		if a, ok := rec.RData().(rdata.A); ok {
			fmt.Println("www.example.com A:", a.Addr())
		}
	}

	// OUTPUT:
	// www.example.com A: 192.0.2.42
}
