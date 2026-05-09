package ixfr_test

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/ixfr"
	"github.com/lestrrat-go/acidns/tsig"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/stretchr/testify/require"
)

type programmableStreamEx struct {
	gotQ    wire.Message
	makeMsg func(reqMAC []byte) []wire.Message
	key     tsig.Key
	now     time.Time
	fudge   time.Duration
}

func (p *programmableStreamEx) Exchange(_ context.Context, _ wire.Message) (wire.Message, error) {
	return wire.Message{}, io.EOF
}

func (p *programmableStreamEx) Stream(_ context.Context, q wire.Message) (acidns.MessageStream, error) {
	p.gotQ = q
	raw, err := wire.Marshal(q)
	if err != nil {
		return nil, err
	}
	_, mac, _, err := tsig.VerifyMAC(raw, p.key, p.now, p.fudge)
	if err != nil {
		return nil, err
	}
	return &fakeStream{msgs: p.makeMsg(mac)}, nil
}

func signResp(t *testing.T, m wire.Message, key tsig.Key, requestMAC []byte, now time.Time, fudge time.Duration) wire.Message {
	t.Helper()
	raw, err := wire.Marshal(m)
	require.NoError(t, err)
	signed, err := tsig.SignResponse(raw, key, requestMAC, now, fudge)
	require.NoError(t, err)
	out, err := wire.Unmarshal(signed)
	require.NoError(t, err)
	return out
}

func TestIXFRTSIGSignedQueryAndVerifiedResponse(t *testing.T) {
	t.Parallel()

	key := tsig.NewKey(
		wire.MustParseName("ixfr.key"),
		tsig.HMACSHA256,
		[]byte("0123456789abcdef0123456789abcdef"),
	)
	now := time.Unix(1700000000, 0)

	ex := &programmableStreamEx{
		key:   key,
		now:   now,
		fudge: 5 * time.Minute,
		makeMsg: func(reqMAC []byte) []wire.Message {
			// Up-to-date response: a single SOA matching the client's serial.
			resp, err := wire.NewBuilder().
				ID(1).Response(true).
				Answer(soaRR(100)).
				Build()
			require.NoError(t, err)
			return []wire.Message{signResp(t, resp, key, reqMAC, now, 5*time.Minute)}
		},
	}

	xfer, err := ixfr.Start(t.Context(), ex, wire.MustParseName("example.com"), mkSOA(100),
		ixfr.WithTSIGKey(&key),
		ixfr.WithTSIGClock(func() time.Time { return now }),
	)
	require.NoError(t, err)
	defer func() { _ = xfer.Close() }()

	// Outgoing query carries TSIG.
	var foundTSIG bool
	for _, r := range ex.gotQ.Additionals() {
		if uint16(r.Type()) == 250 {
			foundTSIG = true
			break
		}
	}
	require.True(t, foundTSIG, "outgoing IXFR query must carry TSIG")
	require.Equal(t, ixfr.KindUpToDate, xfer.Kind())

	_, err = xfer.Next(t.Context())
	require.ErrorIs(t, err, io.EOF)
}

func TestIXFRTSIGUnsignedFirstFails(t *testing.T) {
	t.Parallel()

	key := tsig.NewKey(
		wire.MustParseName("ixfr.key"),
		tsig.HMACSHA256,
		[]byte("0123456789abcdef0123456789abcdef"),
	)
	now := time.Unix(1700000000, 0)

	ex := &programmableStreamEx{
		key:   key,
		now:   now,
		fudge: 5 * time.Minute,
		makeMsg: func(_ []byte) []wire.Message {
			resp, err := wire.NewBuilder().ID(1).Response(true).Answer(soaRR(100)).Build()
			require.NoError(t, err)
			return []wire.Message{resp}
		},
	}

	_, err := ixfr.Start(t.Context(), ex, wire.MustParseName("example.com"), mkSOA(100),
		ixfr.WithTSIGKey(&key),
		ixfr.WithTSIGClock(func() time.Time { return now }),
	)
	require.Error(t, err)
	require.True(t, errors.Is(err, ixfr.ErrTSIGVerify))
}
