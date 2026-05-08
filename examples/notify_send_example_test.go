package examples_test

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/authoritative"
	"github.com/lestrrat-go/acidns/notify"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/zonefile"
)

func Example_notify_send() {
	// Run an authoritative server with a NotifyHandler. The handler fires
	// after the server has ACKed the NOTIFY (per RFC 1996), so a real
	// secondary would schedule an IXFR/AXFR fetch from inside this callback.
	var fired atomic.Int32

	z, _ := zonefile.Parse(strings.NewReader(`$ORIGIN example.com.
$TTL 60
@   IN  SOA  ns1.example.com. hm.example.com. ( 1 2 3 4 5 )
@   IN  NS   ns1.example.com.
ns1 IN  A    192.0.2.10
`))
	// NOTIFY is refused by default; install a policy that admits the
	// request (production callers should match w.RemoteAddr() against
	// the configured primaries).
	h, err := authoritative.New(
		authoritative.WithZone(z),
		authoritative.WithNotifyPolicy(func(_ context.Context, _ acidns.ResponseWriter, _ wire.Message) bool { return true }),
		authoritative.WithNotifyHandler(func(_ wire.Question, _ acidns.ResponseWriter) {
			fired.Add(1)
		}),
	)
	if err != nil {
		fmt.Println("auth:", err)
		return
	}
	srv, err := acidns.NewUDPServer(netip.MustParseAddrPort("127.0.0.1:0"), h)
	if err != nil {
		fmt.Println("listen:", err)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctrl, err := srv.Run(ctx)
	if err != nil {
		fmt.Println("run:", err)
		return
	}

	// Send a NOTIFY using the dnsclient/notify helper.
	ex, err := acidns.NewUDPExchanger(ctrl.Addr())
	if err != nil {
		fmt.Println("dial:", err)
		return
	}
	resp, err := notify.Send(ctx, ex, wire.MustParseName("example.com"))
	if err != nil {
		fmt.Println("send:", err)
		return
	}
	fmt.Println("rcode:", resp.Flags().RCODE())
	fmt.Println("authoritative:", resp.Flags().Authoritative())

	// Wait briefly for the handler to fire.
	deadline := time.Now().Add(time.Second)
	for fired.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	fmt.Println("handler fired:", fired.Load())

	// OUTPUT:
	// rcode: NOERROR
	// authoritative: true
	// handler fired: 1
}
