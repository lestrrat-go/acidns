package dnsupdate_test

import (
	"crypto/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient/dnsupdate"
	"github.com/lestrrat-go/acidns/tsig"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/stretchr/testify/require"
)

func TestSignedUpdate(t *testing.T) {
	t.Parallel()

	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	require.NoError(t, err)
	key := tsig.Key{
		Name:      wire.MustParseName("update.key"),
		Algorithm: tsig.HMACSHA256,
		Secret:    secret,
	}

	rec := wire.NewRecord(wire.MustParseName("blog.example.com"), 60*time.Second,
		rdata.NewA(netip.MustParseAddr("198.51.100.5")))

	now := time.Now().Truncate(time.Second)
	msg, err := dnsupdate.NewBuilder(wire.MustParseName("example.com")).
		AddRRset(rec).
		Build()
	require.NoError(t, err)

	signed, err := tsig.SignMessage(msg, key, now, 5*time.Minute)
	require.NoError(t, err)

	body, _, err := tsig.Verify(signed, key, now, 5*time.Minute)
	require.NoError(t, err)

	verified, err := wire.Unmarshal(body)
	require.NoError(t, err)
	require.Equal(t, wire.OpcodeUpdate, verified.Flags().Opcode())
	require.Equal(t, 1, len(verified.Authorities())) // the add-RRset
}
