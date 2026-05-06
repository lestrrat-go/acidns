package examples_test

import (
	"context"
	"fmt"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient"
	"github.com/lestrrat-go/acidns/dnsclient/ddr"
	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
)

// fakeAnswer + fakeResolver give us a network-free DDR demo. In production
// you pass a real Resolver bound to your unencrypted upstream and trust the
// IPv4Hints/IPv6Hints to match the resolver address you bootstrapped from.
type fakeAnswer struct{ records []dnsmsg.Record }

func (f *fakeAnswer) Question() dnsmsg.Question { return nil }
func (f *fakeAnswer) Records() []dnsmsg.Record  { return f.records }
func (f *fakeAnswer) Raw() dnsmsg.Message       { return nil }
func (f *fakeAnswer) RCODE() dnsmsg.RCODE       { return dnsmsg.RCODENoError }
func (f *fakeAnswer) Authoritative() bool       { return false }
func (f *fakeAnswer) Truncated() bool           { return false }

type fakeResolver struct{ records []dnsmsg.Record }

func (f *fakeResolver) Resolve(_ context.Context, _ dnsname.Name, _ rrtype.Type) (dnsclient.Answer, error) {
	return &fakeAnswer{records: f.records}, nil
}

func Example_ddr_discover() {
	// Build a SVCB record advertising a DoH endpoint, exactly as a
	// production resolver would emit it from _dns.resolver.arpa.
	alpn, _ := rdata.NewSvcParamALPN("h2")
	svcb := rdata.NewSVCB(1, dnsname.MustParse("doh.example.net"),
		alpn,
		rdata.NewSvcParamPort(443),
		rdata.NewSvcParamDOHPath("/dns-query{?dns}"),
	)
	r := &fakeResolver{records: []dnsmsg.Record{
		dnsmsg.NewRecord(ddr.ResolverDomain, 60*time.Second, svcb),
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
