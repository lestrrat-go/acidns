package examples_test

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/zonefile/classless"
)

func Example_classless_delegation() {
	// RFC 2317 helper: 192.0.2.0/27 covers 32 reverse-DNS PTR labels
	// (0..31). Each gets a CNAME from the parent /24 zone into a
	// subzone the prefix owner runs.
	prefix := netip.MustParsePrefix("192.0.2.0/27")
	subzone := wire.MustParseName("0-31.2.0.192.in-addr.arpa.")

	recs, err := classless.BuildDelegationCNAMEs(prefix, subzone, time.Hour)
	if err != nil {
		fmt.Println("build:", err)
		return
	}

	fmt.Println("records:", len(recs))
	// First, middle, last to keep output compact and deterministic.
	for _, idx := range []int{0, 15, 31} {
		c, _ := wire.RDataAs[rdata.CNAME](recs[idx])
		fmt.Printf("%s CNAME %s\n", recs[idx].Name(), c.Target())
	}

	// OUTPUT:
	// records: 32
	// 0.2.0.192.in-addr.arpa. CNAME 0.0-31.2.0.192.in-addr.arpa.
	// 15.2.0.192.in-addr.arpa. CNAME 15.0-31.2.0.192.in-addr.arpa.
	// 31.2.0.192.in-addr.arpa. CNAME 31.0-31.2.0.192.in-addr.arpa.
}
