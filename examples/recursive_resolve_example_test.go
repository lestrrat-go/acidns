package examples_test

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/lestrrat-go/acidns/recursive"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// scriptedDialer answers queries directly from in-memory tables, so the
// example exercises the recursive walk without any network I/O.
type scriptedDialer struct {
	root netip.AddrPort
	auth netip.AddrPort
}

func (d scriptedDialer) Exchange(_ context.Context, server netip.AddrPort, q wire.Message) (wire.Message, error) {
	question := q.Questions()[0]
	b := wire.NewMessageBuilder().ID(q.ID()).Response(true).Question(question)

	switch server {
	case d.root:
		// Root returns a referral to the example.com authoritative.
		b = b.Authority(wire.NewRecord(wire.MustParseName("example.com"), time.Minute,
			rdata.MustNewNS(wire.MustParseName("ns1.example.com"))))
		b = b.Additional(wire.NewRecord(wire.MustParseName("ns1.example.com"), time.Minute,
			rdata.MustNewA(netip.MustParseAddr("127.0.0.1"))))
	case d.auth:
		// Authoritative answers the query.
		b = b.Authoritative(true).Answer(wire.NewRecord(question.Name(), time.Minute,
			rdata.MustNewA(netip.MustParseAddr("198.51.100.7"))))
	}

	m, _ := b.Build()
	return m, nil
}

func Example_recursive_resolve() {
	// Pin synthetic server addresses; the dialer translates them to
	// scripted responses, so we never touch the network. The glue
	// address embedded in the root referral (127.0.0.1) is dialed on
	// the default DNS port 53, which the dialer treats as the auth.
	rootAddr := netip.MustParseAddrPort("127.0.0.1:1053")
	authAddr := netip.MustParseAddrPort("127.0.0.1:53")

	r, err := recursive.New(
		recursive.WithRoots(rootAddr),
		recursive.WithDialer(scriptedDialer{root: rootAddr, auth: authAddr}),
	)
	if err != nil {
		fmt.Println("new:", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	entry, err := r.ResolveEntry(ctx, wire.MustParseName("www.example.com"), rrtype.A)
	if err != nil {
		fmt.Println("resolve:", err)
		return
	}

	fmt.Println("rcode:", entry.RCODE())
	fmt.Println("authoritative:", entry.AA())
	for _, rec := range entry.Answer() {
		if a, ok := wire.RDataAs[rdata.A](rec); ok {
			fmt.Println("A:", a.Addr())
		}
	}

	// OUTPUT:
	// rcode: NOERROR
	// authoritative: true
	// A: 198.51.100.7
}
