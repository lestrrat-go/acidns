package examples_test

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/authoritative"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/zonefile"
)

func Example_dnsserver_acl() {
	// acidns.NewACL wraps any Handler so source-IP allow/deny rules apply before
	// the inner handler runs. Denied queries are silently dropped by default
	// (the safe behaviour for public UDP listeners — see WithACLDropDenied).
	z, _ := zonefile.Parse(strings.NewReader(`$ORIGIN example.com.
$TTL 60
@   IN  SOA  ns. hm. ( 1 2 3 4 5 )
@   IN  NS   ns1.example.com.
ns1 IN  A    192.0.2.10
www IN  A    192.0.2.42
`))
	auth, _ := authoritative.New(authoritative.WithZone(z))

	// Allow only loopback. Anyone else is refused.
	guarded, err := acidns.NewACL(auth, acidns.WithACLAllow(netip.MustParsePrefix("127.0.0.0/8")))
	if err != nil {
		fmt.Println("acl:", err)
		return
	}

	srv, err := acidns.NewUDPServer(netip.MustParseAddrPort("127.0.0.1:0"), guarded)
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

	// Loopback request — allowed.
	q, _ := wire.NewMessageBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("www.example.com"), rrtype.A)).
		Build()
	ex, _ := acidns.NewUDPExchanger(ctrl.Addr())
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
