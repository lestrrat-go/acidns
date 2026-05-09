package examples_test

import (
	"context"
	"fmt"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/ddr"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// fakeResolver gives us a network-free DDR demo. In production
// you pass a real Resolver bound to your unencrypted upstream and trust the
// IPv4Hints/IPv6Hints to match the resolver address you bootstrapped from.
type fakeResolver struct{ records []wire.Record }

func (f *fakeResolver) Resolve(_ context.Context, _ wire.Name, _ rrtype.Type) (*acidns.Answer, error) {
	raw, _ := wire.NewBuilder().Response(true).Build()
	return acidns.NewAnswer(nil, f.records, raw), nil
}

func Example_ddr_discover() {
	// Build a SVCB record advertising a DoH endpoint, exactly as a
	// production resolver would emit it from _dns.resolver.arpa.
	alpn, _ := rdata.NewSvcParamALPN("h2")
	svcb, err := rdata.NewSVCB(1, wire.MustParseName("doh.example.net"),
		alpn,
		rdata.NewSvcParamPort(443),
		rdata.NewSvcParamDOHPath("/dns-query{?dns}"),
	)
	if err != nil {
		fmt.Println("svcb:", err)
		return
	}
	r := &fakeResolver{records: []wire.Record{
		wire.NewRecord(ddr.ResolverDomain, 60*time.Second, svcb),
	}}

	endpoints, err := ddr.Discover(context.Background(), r)
	if err != nil {
		fmt.Println("discover:", err)
		return
	}
	for _, e := range endpoints {
		fmt.Printf("priority=%d proto=%s target=%s port=%d path=%s\n",
			e.Priority, e.Protocol, e.Target, e.Port, e.DOHPath)
	}

	// OUTPUT:
	// priority=1 proto=doh target=doh.example.net. port=443 path=/dns-query{?dns}
}
