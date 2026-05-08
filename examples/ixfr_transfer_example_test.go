package examples_test

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/ixfr"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
)

// fakeIXFRStream serves a fixed list of pre-built messages.
type fakeIXFRStream struct {
	msgs []wire.Message
	idx  int
}

func (f *fakeIXFRStream) Next(_ context.Context) (wire.Message, error) {
	if f.idx >= len(f.msgs) {
		return nil, io.EOF
	}
	m := f.msgs[f.idx]
	f.idx++
	return m, nil
}
func (f *fakeIXFRStream) Close() error { return nil }

// fakeIXFRExchanger satisfies acidns.StreamExchanger with a canned stream.
type fakeIXFRExchanger struct{ s acidns.MessageStream }

func (f *fakeIXFRExchanger) Exchange(_ context.Context, _ wire.Message) (wire.Message, error) {
	return nil, io.EOF
}
func (f *fakeIXFRExchanger) Stream(_ context.Context, _ wire.Message) (acidns.MessageStream, error) {
	return f.s, nil
}

func Example_ixfr_transfer() {
	// Build a single-message IXFR response that takes the zone from
	// serial 100 to serial 101: one A record removed, one added.
	soa := func(serial uint32) wire.Record {
		return wire.NewRecord(wire.MustParseName("example.com"), 60*time.Second,
			rdata.NewSOA(
				wire.MustParseName("ns.example.com"),
				wire.MustParseName("hm.example.com"),
				serial,
				7200*time.Second, 3600*time.Second, 1209600*time.Second, 60*time.Second,
			))
	}
	removed := wire.NewRecord(wire.MustParseName("a.example.com"), 60*time.Second,
		rdata.NewA(netip.MustParseAddr("192.0.2.1")))
	added := wire.NewRecord(wire.MustParseName("b.example.com"), 60*time.Second,
		rdata.NewA(netip.MustParseAddr("192.0.2.2")))

	resp, err := wire.NewBuilder().
		ID(1).Response(true).
		Answer(soa(101)). // newSOA
		Answer(soa(100)). // sub-diff start (old serial)
		Answer(removed).
		Answer(soa(101)). // mid-diff: removed → added
		Answer(added).
		Answer(soa(101)). // closing bracket
		Build()
	if err != nil {
		fmt.Println("build:", err)
		return
	}

	clientSOA := rdata.NewSOA(
		wire.MustParseName("ns.example.com"),
		wire.MustParseName("hm.example.com"),
		100,
		7200*time.Second, 3600*time.Second, 1209600*time.Second, 60*time.Second,
	)
	ex := &fakeIXFRExchanger{s: &fakeIXFRStream{msgs: []wire.Message{resp}}}

	xfer, err := ixfr.Start(context.Background(), ex, wire.MustParseName("example.com"), clientSOA)
	if err != nil {
		fmt.Println("ixfr:", err)
		return
	}
	defer func() { _ = xfer.Close() }()

	fmt.Println("incremental:", xfer.Kind() == ixfr.KindIncremental)
	fmt.Println("new serial:", xfer.NewSOA().Serial())

	for {
		ev, err := xfer.Next(context.Background())
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Println("next:", err)
			return
		}
		if d, ok := ev.(ixfr.DiffEvent); ok {
			fmt.Printf("diff %d -> %d: removed=%d added=%d\n",
				d.FromSerial(), d.ToSerial(), len(d.Removed()), len(d.Added()))
		}
	}

	// OUTPUT:
	// incremental: true
	// new serial: 101
	// diff 100 -> 101: removed=1 added=1
}
