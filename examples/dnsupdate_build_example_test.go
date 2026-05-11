package examples_test

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/lestrrat-go/acidns/update"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

func Example_dnsupdate_build() {
	// update.Builder constructs an RFC 2136 UPDATE message. Add a
	// prerequisite, an addition, and a delete; Build returns a wire.Message
	// you can ship over any acidns.Exchanger.
	zone := wire.MustParseName("example.com")
	ar, err := rdata.NewA(netip.MustParseAddr("198.51.100.5"))
	if err != nil {
		fmt.Println("a:", err)
		return
	}
	rec := wire.NewRecord(
		wire.MustParseName("blog.example.com"),
		60*time.Second,
		ar,
	)

	msg, err := update.NewBuilder(zone).
		PrereqNameNotInUse(wire.MustParseName("blog.example.com")).
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
