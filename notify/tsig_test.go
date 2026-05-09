package notify_test

import (
	"context"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/notify"
	"github.com/lestrrat-go/acidns/tsig"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/stretchr/testify/require"
)

// captureExchanger records the query Message and returns a canned response.
type captureExchanger struct {
	got  wire.Message
	resp wire.Message
}

func (c *captureExchanger) Exchange(_ context.Context, q wire.Message) (wire.Message, error) {
	c.got = q
	return c.resp, nil
}

func TestNotifySignedQueryHasTSIG(t *testing.T) {
	t.Parallel()

	key := tsig.NewKey(
		wire.MustParseName("notify.key"),
		tsig.HMACSHA256,
		[]byte("0123456789abcdef0123456789abcdef"),
	)

	resp, err := wire.NewBuilder().
		ID(1).
		Opcode(wire.OpcodeNotify).
		Response(true).
		RCODE(wire.RCODENoError).
		Build()
	require.NoError(t, err)

	ex := &captureExchanger{resp: resp}
	now := time.Unix(1700000000, 0)

	_, err = notify.Send(t.Context(), ex, wire.MustParseName("example.com"),
		notify.WithTSIGKey(&key),
		notify.WithTSIGClock(func() time.Time { return now }),
	)
	require.NoError(t, err)

	require.NotNil(t, ex.got)

	// The captured query should carry a TSIG RR (type 250) in additional.
	var foundTSIG bool
	for _, r := range ex.got.Additionals() {
		if uint16(r.Type()) == 250 {
			foundTSIG = true
			require.True(t, r.Name().Equal(wire.MustParseName("notify.key")))
			break
		}
	}
	require.True(t, foundTSIG, "outgoing NOTIFY must carry a TSIG RR in additional")
}

// roundTripExchanger marshals the inbound query (so a signed query's
// bytes are visible) and constructs an unsigned response.
type roundTripExchanger struct {
	got []byte
	key tsig.Key
	now time.Time
}

func (r *roundTripExchanger) Exchange(_ context.Context, q wire.Message) (wire.Message, error) {
	raw, err := wire.Marshal(q)
	if err != nil {
		return wire.Message{}, err
	}
	r.got = raw
	resp, err := wire.NewBuilder().ID(q.ID()).Opcode(wire.OpcodeNotify).Response(true).Build()
	return resp, err
}

func TestNotifySignedQueryRoundTripVerifies(t *testing.T) {
	t.Parallel()

	key := tsig.NewKey(
		wire.MustParseName("notify.key"),
		tsig.HMACSHA256,
		[]byte("abcdefabcdefabcdefabcdefabcdef00"),
	)
	now := time.Unix(1700000000, 0)

	ex := &roundTripExchanger{key: key, now: now}
	_, err := notify.Send(t.Context(), ex, wire.MustParseName("example.com"),
		notify.WithTSIGKey(&key),
		notify.WithTSIGClock(func() time.Time { return now }),
	)
	require.NoError(t, err)

	// The bytes the exchanger saw should still verify under the key.
	body, _, err := tsig.Verify(ex.got, key, now, 5*time.Minute)
	require.NoError(t, err)
	require.NotNil(t, body)
}
