package examples_test

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient/transport/udp"
	"github.com/lestrrat-go/acidns/dnsserver"
	"github.com/lestrrat-go/acidns/dnsserver/acl"
	"github.com/lestrrat-go/acidns/authoritative"
	"github.com/lestrrat-go/acidns/zonefile"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

func Example_dnsserver_acl() {
	// acl.New wraps any Handler so source-IP allow/deny rules apply before
	// the inner handler runs. Denied queries get REFUSED.
	z, _ := zonefile.Parse(strings.NewReader(`$ORIGIN example.com.
$TTL 60
@   IN  SOA  ns. hm. ( 1 2 3 4 5 )
@   IN  NS   ns1.example.com.
ns1 IN  A    192.0.2.10
www IN  A    192.0.2.42
`))
	auth, _ := authoritative.New(authoritative.WithZone(z))

	// Allow only loopback. Anyone else is refused.
	guarded := acl.New(auth, acl.WithAllow(netip.MustParsePrefix("127.0.0.0/8")))

	srv, err := dnsserver.ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"), guarded)
	if err != nil {
		fmt.Println("listen:", err)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()

	// Loopback request — allowed.
	q, _ := wire.NewBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("www.example.com"), rrtype.A)).
		Build()
	ex, _ := udp.New(srv.Addr())
	qctx, qcancel := context.WithTimeout(ctx, 2*time.Second)
	defer qcancel()
	resp, err := ex.Exchange(qctx, q)
	if err != nil {
		fmt.Println("exchange:", err)
		return
	}
	fmt.Println("rcode:", resp.Flags().RCODE())
	fmt.Println("answers:", len(resp.Answers()))

	// OUTPUT:
	// rcode: NOERROR
	// answers: 1
}
