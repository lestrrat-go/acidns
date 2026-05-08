package examples_test

import (
	"context"
	"fmt"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/amt"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// stubAnswer is a minimal acidns.Answer used to feed scripted records to
// amt.Discover without going through a real resolver.
type stubAnswer struct{ records []wire.Record }

func (a *stubAnswer) Question() wire.Question { return nil }
func (a *stubAnswer) Records() []wire.Record  { return a.records }
func (a *stubAnswer) Raw() wire.Message       { return nil }
func (a *stubAnswer) RCODE() wire.RCODE       { return wire.RCODENoError }
func (a *stubAnswer) Authoritative() bool     { return false }
func (a *stubAnswer) Truncated() bool         { return false }

// stubResolver hands every Resolve call the same record list.
type stubResolver struct{ records []wire.Record }

func (s *stubResolver) Resolve(_ context.Context, _ wire.Name, _ rrtype.Type) (acidns.Answer, error) {
	return &stubAnswer{records: s.records}, nil
}

func Example_amt_discover() {
	// Three SRV candidates for `_amt._udp.example.com.`. Discover sorts
	// by priority ascending; weight ties preserve server-supplied order.
	r := &stubResolver{
		records: []wire.Record{
			wire.NewRecord(wire.MustParseName("_amt._udp.example.com"), 60*time.Second,
				rdata.NewSRV(20, 0, 2268, wire.MustParseName("relay-b.example.com"))),
			wire.NewRecord(wire.MustParseName("_amt._udp.example.com"), 60*time.Second,
				rdata.NewSRV(10, 0, 2268, wire.MustParseName("relay-a.example.com"))),
			wire.NewRecord(wire.MustParseName("_amt._udp.example.com"), 60*time.Second,
				rdata.NewSRV(10, 50, 2268, wire.MustParseName("relay-c.example.com"))),
		},
	}

	relays, err := amt.Discover(context.Background(), r, wire.MustParseName("example.com"))
	if err != nil {
		fmt.Println("discover:", err)
		return
	}

	for _, rl := range relays {
		fmt.Printf("prio=%d weight=%d port=%d %s\n", rl.Priority, rl.Weight, rl.Port, rl.Target)
	}

	// OUTPUT:
	// prio=10 weight=0 port=2268 relay-a.example.com.
	// prio=10 weight=50 port=2268 relay-c.example.com.
	// prio=20 weight=0 port=2268 relay-b.example.com.
}
