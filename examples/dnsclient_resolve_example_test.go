package examples_test

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/authoritative"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/zonefile"
)

// startLocalNS is a tiny shared helper: spin up an authoritative server bound
// to localhost. Each server-using example wires its own copy so the example
// reads top-to-bottom without scanning utilities.
func startLocalNS(ctx context.Context, zoneText string) (netip.AddrPort, error) {
	z, err := zonefile.Parse(strings.NewReader(zoneText))
	if err != nil {
		return netip.AddrPort{}, err
	}
	h, err := authoritative.New(authoritative.WithZone(z))
	if err != nil {
		return netip.AddrPort{}, err
	}
	srv, err := acidns.NewUDPServer(netip.MustParseAddrPort("127.0.0.1:0"), h)
	if err != nil {
		return netip.AddrPort{}, err
	}
	ctrl, err := srv.Run(ctx)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return ctrl.Addr(), nil
}

func Example_dnsclient_resolve() {
	// Resolve is the single primitive on acidns.Resolver: name + type
	// in, Answer out. Errors carry a typed *RCodeError when the response
	// has a non-NoError RCODE.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr, err := startLocalNS(ctx, `$ORIGIN example.com.
$TTL 60
@   IN  SOA  ns1.example.com. hm.example.com. ( 1 7200 3600 1209600 60 )
@   IN  NS   ns1.example.com.
mail IN A    192.0.2.10
mail IN A    192.0.2.11
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
	ans, err := r.Resolve(qctx, wire.MustParseName("mail.example.com"), rrtype.A)
	if err != nil {
		fmt.Println("resolve:", err)
		return
	}

	// Sort for deterministic output — the server may emit records in
	// either order.
	addrs := make([]string, 0, len(ans.Records()))
	for _, rec := range ans.Records() {
		if a, ok := rec.RData().(rdata.A); ok {
			addrs = append(addrs, a.Addr().String())
		}
	}
	sort.Strings(addrs)
	for _, s := range addrs {
		fmt.Println(s)
	}

	// OUTPUT:
	// 192.0.2.10
	// 192.0.2.11
}
