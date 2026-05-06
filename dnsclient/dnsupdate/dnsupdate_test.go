package dnsupdate_test

import (
	"crypto/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient/dnsupdate"
	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/lestrrat-go/acidns/tsig"
	"github.com/stretchr/testify/require"
)

func TestSignedUpdate(t *testing.T) {
	t.Parallel()

	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	require.NoError(t, err)
	key := tsig.Key{
		Name:      dnsname.MustParse("update.key"),
		Algorithm: tsig.HMACSHA256,
		Secret:    secret,
	}

	rec := dnsmsg.NewRecord(dnsname.MustParse("blog.example.com"), 60*time.Second,
		rdata.NewA(netip.MustParseAddr("198.51.100.5")))

	now := time.Now().Truncate(time.Second)
	msg, err := dnsupdate.NewBuilder(dnsname.MustParse("example.com")).
		AddRRset(rec).
		Build()
	require.NoError(t, err)

	signed, err := tsig.SignMessage(msg, key, now, 5*time.Minute)
	require.NoError(t, err)

	body, _, err := tsig.Verify(signed, key, now, 5*time.Minute)
	require.NoError(t, err)

	verified, err := dnsmsg.Unmarshal(body)
	require.NoError(t, err)
	require.Equal(t, dnsmsg.OpcodeUpdate, verified.Flags().Opcode())
	require.Equal(t, 1, len(verified.Authorities())) // the add-RRset
}
