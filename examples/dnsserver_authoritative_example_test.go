package examples_test

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/lestrrat-go/acidns/dnsserver"
	"github.com/lestrrat-go/acidns/dnsserver/authoritative"
	"github.com/lestrrat-go/acidns/dnszone"
)

func Example_dnsserver_authoritative() {
	// authoritative.New + dnsserver.ListenUDP boot a serving authoritative
	// nameserver in-process. Useful for tests and toy deployments.
	z, _ := dnszone.Parse(strings.NewReader(`$ORIGIN example.com.
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
	ans, err := r.Resolve(qctx, dnsname.MustParse("www.example.com"), rrtype.A)
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
