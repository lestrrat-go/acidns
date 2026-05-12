package axfr_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/tsig"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

func TestTSIGMarshalRoundtripIsStable(t *testing.T) {
	t.Parallel()

	key, err := tsig.NewKey(
		wire.MustParseName("xfr.key"),
		tsig.HMACSHA256,
		[]byte("0123456789abcdef0123456789abcdef"),
	)
	require.NoError(t, err)
	now := time.Unix(1700000000, 0)

	soa := soaRec(t, 7)
	resp := answerMsg(t, soa, soa)
	raw, err := wire.Pack(resp)
	require.NoError(t, err)
	signed, err := tsig.Sign(raw, key, now, 5*time.Minute)
	require.NoError(t, err)

	rt, err := wire.Unpack(signed)
	require.NoError(t, err)
	rtMarshaled, err := wire.Pack(rt)
	require.NoError(t, err)

	if !bytes.Equal(signed, rtMarshaled) {
		t.Logf("signed   bytes: %x", signed)
		t.Logf("rt bytes      : %x", rtMarshaled)
		t.Fatalf("re-marshal NOT byte-stable (len signed=%d, len rt=%d)", len(signed), len(rtMarshaled))
	}

	// Also try with a question section (closer to a real AXFR response).
	respQ, err := wire.NewMessageBuilder().Response(true).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.AXFR)).
		Answer(soa).Answer(soa).Build()
	require.NoError(t, err)
	rawQ, err := wire.Pack(respQ)
	require.NoError(t, err)
	signedQ, err := tsig.Sign(rawQ, key, now, 5*time.Minute)
	require.NoError(t, err)

	rtQ, err := wire.Unpack(signedQ)
	require.NoError(t, err)
	rtQMarshaled, err := wire.Pack(rtQ)
	require.NoError(t, err)

	if !bytes.Equal(signedQ, rtQMarshaled) {
		t.Logf("signed   bytes: %x", signedQ)
		t.Logf("rt bytes      : %x", rtQMarshaled)
		t.Fatalf("re-marshal NOT byte-stable with question (len signed=%d, len rt=%d)", len(signedQ), len(rtQMarshaled))
	}
}
