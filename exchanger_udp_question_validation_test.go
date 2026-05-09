package acidns_test

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// TestUDPExchangerRejectsMismatchedQuestion confirms that a response
// whose ID matches but whose question section does not is dropped. RFC
// 5452 §9.2: ID-only validation lets an attacker who guesses the 16-bit
// transaction ID poison the cache; the question section must also match.
func TestUDPExchangerRejectsMismatchedQuestion(t *testing.T) {
	t.Parallel()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })

	// Server: replies with the correct ID but answers a different question.
	go func() {
		buf := make([]byte, 4096)
		for {
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			req, err := wire.Unmarshal(buf[:n])
			if err != nil {
				continue
			}
			// Build a "spoofed" answer for the wrong name.
			spoofedQ := wire.NewQuestion(wire.MustParseName("attacker.example"), rrtype.A)
			ans := wire.NewRecord(wire.MustParseName("attacker.example"), 60*time.Second,
				rdata.MustNewA(netip.MustParseAddr("198.51.100.66")))
			resp, err := wire.NewBuilder().
				ID(req.ID()).
				Response(true).
				Question(spoofedQ).
				Answer(ans).
				Build()
			if err != nil {
				continue
			}
			b, _ := wire.Marshal(resp)
			_, _ = pc.WriteTo(b, src)
		}
	}()

	addr := netip.AddrPortFrom(
		netip.MustParseAddr("127.0.0.1"),
		uint16(pc.LocalAddr().(*net.UDPAddr).Port))

	ex, err := acidns.NewUDPExchanger(addr, acidns.WithUDPTimeout(300*time.Millisecond))
	require.NoError(t, err)

	q, err := wire.NewBuilder().
		ID(0xbeef).
		Question(wire.NewQuestion(wire.MustParseName("real.example"), rrtype.A)).
		Build()
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 800*time.Millisecond)
	defer cancel()
	_, err = ex.Exchange(ctx, q)
	require.Error(t, err,
		"exchanger must reject responses whose question doesn't match the request")
}
