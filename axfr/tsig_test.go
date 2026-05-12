package axfr_test

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/axfr"
	"github.com/lestrrat-go/acidns/tsig"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/stretchr/testify/require"
)

// signResponseMsg signs a wire.Message as the first AXFR response and
// returns the resulting wire.Message and its MAC.
func signResponseMsg(t *testing.T, m wire.Message, key tsig.Key, requestMAC []byte, now time.Time, fudge time.Duration) (wire.Message, []byte) {
	t.Helper()
	raw, err := wire.Pack(m)
	require.NoError(t, err)
	signed, err := signResponseRaw(raw, key, requestMAC, now, fudge)
	require.NoError(t, err)
	out, err := wire.Unpack(signed)
	require.NoError(t, err)
	mac := extractMAC(t, signed, key, now, fudge, requestMAC)
	return out, mac
}

func signResponseRaw(raw []byte, key tsig.Key, requestMAC []byte, now time.Time, fudge time.Duration) ([]byte, error) {
	return tsig.SignResponse(raw, key, requestMAC, now, fudge)
}

func extractMAC(t *testing.T, signed []byte, key tsig.Key, now time.Time, fudge time.Duration, requestMAC []byte) []byte {
	t.Helper()
	_, mac, _, err := tsig.VerifyResponse(signed, key, requestMAC, now, fudge)
	require.NoError(t, err)
	return mac
}

// programmableStreamEx invokes a per-call factory after capturing the
// signed query, letting the test build response messages whose TSIG
// chains the actual request MAC.
type programmableStreamEx struct {
	gotQ    wire.Message
	makeMsg func(reqMAC []byte) []wire.Message
	key     tsig.Key
	now     time.Time
	fudge   time.Duration
}

func (p *programmableStreamEx) Stream(_ context.Context, q wire.Message) (acidns.MessageStream, error) {
	p.gotQ = q
	raw, err := wire.Pack(q)
	if err != nil {
		return nil, err
	}
	_, mac, _, err := tsig.VerifyMAC(raw, p.key, p.now, p.fudge)
	if err != nil {
		return nil, err
	}
	msgs := p.makeMsg(mac)
	// Stamp the originating request ID onto each canned envelope so the
	// recReader's RFC 5936 §3.4 envelope-ID check accepts them.
	for i, m := range msgs {
		if m.ID() == 0 {
			msgs[i] = wire.WithID(m, q.ID())
		}
	}
	return &fakeStream{msgs: msgs}, nil
}

func TestAXFRTSIGSignedQueryAndVerifiedResponse(t *testing.T) {
	t.Parallel()

	key, err := tsig.NewKey(
		wire.MustParseName("xfr.key"),
		tsig.HMACSHA256,
		[]byte("0123456789abcdef0123456789abcdef"),
	)
	require.NoError(t, err)
	now := time.Unix(1700000000, 0)

	// Build the response factory: signs the response using the actual
	// request MAC produced by the client.
	soa := soaRec(t, 7)
	respM := answerMsg(t, soa, aRec(t, "a.example.com", "192.0.2.1"), soa)
	ex := &programmableStreamEx{
		key:   key,
		now:   now,
		fudge: 5 * time.Minute,
		makeMsg: func(reqMAC []byte) []wire.Message {
			signedResp, _ := signResponseMsg(t, respM, key, reqMAC, now, 5*time.Minute)
			return []wire.Message{signedResp}
		},
	}

	xfer, err := axfr.Start(t.Context(), ex, wire.MustParseName("example.com"),
		axfr.WithTSIGKey(&key),
		axfr.WithTSIGClock(func() time.Time { return now }),
	)
	require.NoError(t, err)
	defer func() { _ = xfer.Close() }()

	// Captured query should carry a TSIG.
	var foundTSIG bool
	for _, r := range ex.gotQ.Additionals() {
		if uint16(r.Type()) == 250 {
			foundTSIG = true
			break
		}
	}
	require.True(t, foundTSIG, "outgoing AXFR query must carry TSIG")

	// Drain the transfer.
	for {
		_, err := xfer.Next(t.Context())
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
	}
}

func TestAXFRTSIGUnsignedFirstFails(t *testing.T) {
	t.Parallel()

	key, err := tsig.NewKey(
		wire.MustParseName("xfr.key"),
		tsig.HMACSHA256,
		[]byte("0123456789abcdef0123456789abcdef"),
	)
	require.NoError(t, err)
	now := time.Unix(1700000000, 0)

	soa := soaRec(t, 7)
	ex := &programmableStreamEx{
		key:   key,
		now:   now,
		fudge: 5 * time.Minute,
		makeMsg: func(_ []byte) []wire.Message {
			// Server "forgets" to sign — verification must fail.
			return []wire.Message{answerMsg(t, soa, soa)}
		},
	}

	_, err = axfr.Start(t.Context(), ex, wire.MustParseName("example.com"),
		axfr.WithTSIGKey(&key),
		axfr.WithTSIGClock(func() time.Time { return now }),
	)
	require.Error(t, err)
	require.ErrorIs(t, err, axfr.ErrTSIGVerify)
}
