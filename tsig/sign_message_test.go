package tsig_test

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/tsig"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

func TestSignMessageRoundTrip(t *testing.T) {
	t.Parallel()
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	require.NoError(t, err)
	key, err := tsig.NewKey(wire.MustParseName("k.example"), tsig.HMACSHA256, secret)
	require.NoError(t, err)
	q, err := wire.NewMessageBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	require.NoError(t, err)

	now := time.Now().Truncate(time.Second)
	signed, err := tsig.SignMessage(q, key, now, 5*time.Minute)
	require.NoError(t, err)
	require.NotEmpty(t, signed)

	body, _, err := tsig.Verify(signed, key, now, 5*time.Minute)
	require.NoError(t, err)
	require.NotEmpty(t, body)
}
