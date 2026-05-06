package tsig_test

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/lestrrat-go/acidns/tsig"
	"github.com/stretchr/testify/require"
)

func TestSignMessageRoundTrip(t *testing.T) {
	t.Parallel()
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	require.NoError(t, err)
	key := tsig.Key{
		Name:      dnsname.MustParse("k.example"),
		Algorithm: tsig.HMACSHA256,
		Secret:    secret,
	}
	q, err := dnsmsg.NewBuilder().
		ID(1).
		Question(dnsmsg.NewQuestion(dnsname.MustParse("example.com"), rrtype.A)).
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
