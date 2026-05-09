package examples_test

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/lestrrat-go/acidns/chaos"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// chaosCaptureWriter is a minimal acidns.ResponseWriter that just records
// the response message handed to WriteMsg.
type chaosCaptureWriter struct{ resp wire.Message }

func (c *chaosCaptureWriter) WriteMsg(m wire.Message) error { c.resp = m; return nil }
func (c *chaosCaptureWriter) RemoteAddr() netip.AddrPort    { return netip.AddrPort{} }
func (c *chaosCaptureWriter) LocalAddr() netip.AddrPort     { return netip.AddrPort{} }
func (c *chaosCaptureWriter) Network() string               { return "udp" }

func Example_chaos_handler() {
	// Build the handler directly — no server framework, just call
	// ServeDNS with a captured writer. Demonstrates RFC 4892 mapping:
	// id.server / hostname.bind both yield the configured identifier;
	// version.server / version.bind both yield the configured version.
	h, err := chaos.New(
		chaos.WithIdentifier("ns1.example.net"),
		chaos.WithVersion("acidns/dev"),
	)
	if err != nil {
		fmt.Println("chaos:", err)
		return
	}

	ask := func(name string) {
		q, _ := wire.NewMessageBuilder().
			ID(1).
			Question(wire.NewQuestionClass(wire.MustParseName(name), rrtype.TXT, rrtype.ClassCH)).
			Build()
		w := &chaosCaptureWriter{}
		h.ServeDNS(context.Background(), w, q)
		txt, _ := wire.RDataAs[rdata.TXT](w.resp.Answers()[0])
		fmt.Printf("%s -> %v\n", name, txt.Strings())
	}

	ask("id.server.")
	ask("hostname.bind.")
	ask("version.server.")
	ask("version.bind.")

	// OUTPUT:
	// id.server. -> [ns1.example.net]
	// hostname.bind. -> [ns1.example.net]
	// version.server. -> [acidns/dev]
	// version.bind. -> [acidns/dev]
}
