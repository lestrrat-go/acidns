package examples_test

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
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

// startLocalNS is a tiny shared helper: spin up an authoritative server bound
// to localhost. Each server-using example wires its own copy so the example
// reads top-to-bottom without scanning utilities.
func startLocalNS(ctx context.Context, zoneText string) (netip.AddrPort, error) {
	z, err := dnszone.Parse(strings.NewReader(zoneText))
	if err != nil {
		return netip.AddrPort{}, err
	}
	h, err := authoritative.New(authoritative.WithZone(z))
	if err != nil {
		return netip.AddrPort{}, err
	}
	srv, err := dnsserver.ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"), h)
	if err != nil {
		return netip.AddrPort{}, err
	}
	go func() { _ = srv.Serve(ctx) }()
	return srv.Addr(), nil
}

func Example_dnsclient_resolve() {
	// Resolve is the single primitive on dnsclient.Resolver: name + type
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

	r, err := dnsclient.New(dnsclient.WithServers(addr))
	if err != nil {
		fmt.Println("client:", err)
		return
	}
	qctx, qcancel := context.WithTimeout(ctx, 2*time.Second)
	defer qcancel()
	ans, err := r.Resolve(qctx, dnsname.MustParse("mail.example.com"), rrtype.A)
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
