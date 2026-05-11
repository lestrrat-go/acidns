package forward

import (
	"context"
	"net/netip"
	"testing"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// captureExchanger records the IDs of incoming queries. The udp form
// returns a TC=1 response (so the fallback triggers); the tcp form
// returns a clean response.
type captureExchanger struct {
	ids []uint16
	tc  bool
}

func (c *captureExchanger) Exchange(_ context.Context, q wire.Message) (wire.Message, error) {
	c.ids = append(c.ids, q.ID())
	b := wire.NewMessageBuilder().
		ID(q.ID()).
		Response(true)
	if len(q.Questions()) > 0 {
		b = b.Question(q.Questions()[0])
	}
	if c.tc {
		b = b.Truncated(true)
	}
	m, err := b.Build()
	if err != nil {
		return wire.Message{}, err
	}
	return m, nil
}

// TestUDPTCPFallbackReRandomizesID is a security-regression guard for
// the fix that re-mints a fresh transaction ID before retrying over
// TCP on a TC=1 response. Re-using the UDP-side ID hands an off-path
// observer a free correlation point (RFC 5452 §10).
func TestUDPTCPFallbackReRandomizesID(t *testing.T) {
	t.Parallel()
	udp := &captureExchanger{tc: true}
	tcp := &captureExchanger{}
	e := &udpTCPFallback{
		addr: netip.MustParseAddrPort("127.0.0.1:53"),
		udp:  udp,
		tcp:  tcp,
	}

	q, err := wire.NewMessageBuilder().
		ID(0x1234).
		Question(wire.NewQuestion(wire.MustParseName("example.com."), rrtype.A)).
		Build()
	require.NoError(t, err)

	_, err = e.Exchange(t.Context(), q)
	require.NoError(t, err)

	require.Len(t, udp.ids, 1)
	require.Len(t, tcp.ids, 1)
	require.Equal(t, uint16(0x1234), udp.ids[0])
	require.NotEqual(t, udp.ids[0], tcp.ids[0],
		"TCP fallback must use a freshly-randomised transaction ID; reusing the UDP ID weakens off-path spoofing defence (RFC 5452 §10)")
}
