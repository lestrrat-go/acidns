package examples_test

import (
	"context"
	"fmt"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

func Example_dnsclient_resolveas() {
	// ResolveAs is a generic helper: it queries for the right RR type and
	// returns the typed rdata directly, skipping the cast you'd do with
	// Resolve.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr, err := startLocalNS(ctx, `$ORIGIN example.com.
$TTL 60
@    IN  SOA  ns. hm. ( 1 7200 3600 1209600 60 )
@    IN  NS   ns1.example.com.
www  IN  A    192.0.2.42
`)
	if err != nil {
		fmt.Println("setup:", err)
		return
	}

	r, err := acidns.NewResolver(acidns.WithServers(addr))
	if err != nil {
		fmt.Println("client:", err)
		return
	}
	qctx, qcancel := context.WithTimeout(ctx, 2*time.Second)
	defer qcancel()
	addrs, err := acidns.ResolveAs[rdata.A](qctx, r, wire.MustParseName("www.example.com"), rrtype.A)
	if err != nil {
		fmt.Println("resolve:", err)
		return
	}
	for _, a := range addrs {
		fmt.Println(a.Addr())
	}

	// OUTPUT:
	// 192.0.2.42
}
