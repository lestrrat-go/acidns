package examples_test

import (
	"fmt"
	"time"

	"github.com/lestrrat-go/acidns/dso"
)

func Example_dso_tlv() {
	// Build a DSO message with a primary KeepAlive TLV and a padding TLV.
	pad, _ := dso.NewEncryptionPadding(8)
	m := &dso.Message{
		Primary:    dso.NewKeepAlive(30*time.Second, 5*time.Second),
		Additional: []dso.TLV{pad},
	}
	wire, err := m.Pack()
	if err != nil {
		fmt.Println("pack:", err)
		return
	}

	// Round-trip.
	decoded, err := dso.Unpack(wire)
	if err != nil {
		fmt.Println("unpack:", err)
		return
	}
	in, ka, ok := dso.KeepAlive(decoded.Primary)
	fmt.Println("keepalive ok:", ok)
	fmt.Println("inactivity:", in)
	fmt.Println("interval:", ka)
	fmt.Println("padding bytes:", len(decoded.Additional[0].Data))

	// OUTPUT:
	// keepalive ok: true
	// inactivity: 30s
	// interval: 5s
	// padding bytes: 8
}
