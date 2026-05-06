package examples_test

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient/dnsupdate"
	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
)

func Example_dnsupdate_build() {
	// dnsupdate.Builder constructs an RFC 2136 UPDATE message. Add a
	// prerequisite, an addition, and a delete; Build returns a dnsmsg.Message
	// you can ship over any transport.Exchanger.
	zone := dnsname.MustParse("example.com")
	rec := dnsmsg.NewRecord(
		dnsname.MustParse("blog.example.com"),
		60*time.Second,
		rdata.NewA(netip.MustParseAddr("198.51.100.5")),
	)

	msg, err := dnsupdate.NewBuilder(zone).
		PrereqNameNotInUse(dnsname.MustParse("blog.example.com")).
		AddRRset(rec).
		Build()
	if err != nil {
		fmt.Println("build:", err)
		return
	}

	fmt.Println("opcode:", msg.Flags().Opcode())
	fmt.Println("zone (qsection):", msg.Questions()[0].Name())
	fmt.Println("prerequisites:", len(msg.Answers()))
	fmt.Println("updates:", len(msg.Authorities()))
	fmt.Println("update class:", msg.Authorities()[0].Class(),
		"type:", msg.Authorities()[0].Type(),
		"ttl:", int(msg.Authorities()[0].TTL().Seconds()))
	_ = rrtype.A

	// OUTPUT:
	// opcode: UPDATE
	// zone (qsection): example.com.
	// prerequisites: 1
	// updates: 1
	// update class: IN type: A ttl: 60
}
