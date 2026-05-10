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

// signingExchanger captures the inbound query, extracts its TSIG MAC,
// and returns a TSIG-signed unsigned response covered by that MAC.
type signingExchanger struct {
	got wire.Message
	key tsig.Key
	now time.Time
}

func (s *signingExchanger) Exchange(_ context.Context, q wire.Message) (wire.Message, error) {
	s.got = q
	raw, err := wire.Marshal(q)
	if err != nil {
		return wire.Message{}, err
	}
	_, mac, _, err := tsig.VerifyMAC(raw, s.key, s.now, 5*time.Minute)
	if err != nil {
		return wire.Message{}, err
	}
	resp, err := wire.NewMessageBuilder().
		ID(q.ID()).
		Opcode(wire.OpcodeNotify).
		Response(true).
		RCODE(wire.RCODENoError).
		Build()
	if err != nil {
		return wire.Message{}, err
	}
	respRaw, err := wire.Marshal(resp)
	if err != nil {
		return wire.Message{}, err
	}
	signed, err := tsig.SignResponse(respRaw, s.key, mac, s.now, 5*time.Minute)
	if err != nil {
		return wire.Message{}, err
	}
	return wire.Unmarshal(signed)
}

// unsignedExchanger ignores its input and returns a fixed unsigned response.
type unsignedExchanger struct {
	got  wire.Message
	resp wire.Message
}

func (u *unsignedExchanger) Exchange(_ context.Context, q wire.Message) (wire.Message, error) {
	u.got = q
	return u.resp, nil
}

func TestNotifySignedQueryHasTSIG(t *testing.T) {
	t.Parallel()

	key := tsig.NewKey(
		wire.MustParseName("notify.key"),
		tsig.HMACSHA256,
		[]byte("0123456789abcdef0123456789abcdef"),
	)
	now := time.Unix(1700000000, 0)
	ex := &signingExchanger{key: key, now: now}

	_, err := notify.Send(t.Context(), ex, wire.MustParseName("example.com"),
		notify.WithTSIGKey(&key),
		notify.WithTSIGClock(func() time.Time { return now }),
	)
	require.NoError(t, err)

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

func TestNotifyUnsignedResponseRejectedWhenSigned(t *testing.T) {
	t.Parallel()

	key := tsig.NewKey(
		wire.MustParseName("notify.key"),
		tsig.HMACSHA256,
		[]byte("0123456789abcdef0123456789abcdef"),
	)
	resp, err := wire.NewMessageBuilder().
		ID(1).
		Opcode(wire.OpcodeNotify).
		Response(true).
		RCODE(wire.RCODENoError).
		Build()
	require.NoError(t, err)

	ex := &unsignedExchanger{resp: resp}
	now := time.Unix(1700000000, 0)
	_, err = notify.Send(t.Context(), ex, wire.MustParseName("example.com"),
		notify.WithTSIGKey(&key),
		notify.WithTSIGClock(func() time.Time { return now }),
	)
	require.ErrorIs(t, err, notify.ErrTSIGMissing)
}

// captureSigningExchanger is signingExchanger plus the raw query bytes,
// so a separate-key verification at test scope can confirm the signed
// query bytes round-trip.
type captureSigningExchanger struct {
	signingExchanger
	got []byte
}

func (r *captureSigningExchanger) Exchange(ctx context.Context, q wire.Message) (wire.Message, error) {
	raw, err := wire.Marshal(q)
	if err != nil {
		return wire.Message{}, err
	}
	r.got = raw
	return r.signingExchanger.Exchange(ctx, q)
}

func TestNotifySignedQueryRoundTripVerifies(t *testing.T) {
	t.Parallel()

	key := tsig.NewKey(
		wire.MustParseName("notify.key"),
		tsig.HMACSHA256,
		[]byte("abcdefabcdefabcdefabcdefabcdef00"),
	)
	now := time.Unix(1700000000, 0)

	ex := &captureSigningExchanger{signingExchanger: signingExchanger{key: key, now: now}}
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
