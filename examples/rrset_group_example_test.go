package examples_test

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
)

func Example_rrset_group() {
	// GroupRecords partitions a flat record list into RRsets per RFC 2181.
	// Mixed TTLs harmonise to the minimum (§5.2).
	name := wire.MustParseName("example.com")
	records := []wire.Record{
		wire.NewRecord(name, 60*time.Second, rdata.NewA(netip.MustParseAddr("192.0.2.1"))),
		wire.NewRecord(name, 30*time.Second, rdata.NewA(netip.MustParseAddr("192.0.2.2"))),
		wire.NewRecord(name, 60*time.Second, rdata.NewAAAA(netip.MustParseAddr("2001:db8::1"))),
	}

	groups, err := wire.GroupRecords(records)
	if err != nil {
		fmt.Println("group:", err)
		return
	}

	for _, g := range groups {
		fmt.Printf("%s %s %d records, ttl=%v\n", g.Name(), g.Type(), g.Len(), g.TTL())
	}

	// OUTPUT:
	// example.com. A 2 records, ttl=30s
	// example.com. AAAA 1 records, ttl=1m0s
}
