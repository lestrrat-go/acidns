package dot_test

import (
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient/transport"
	"github.com/lestrrat-go/acidns/dnsclient/transport/dot"
	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/stretchr/testify/require"
)

func TestDoTStream(t *testing.T) {
	t.Parallel()
	addr, cfg := startDoT(t)
	ex, err := dot.New(addr,
		dot.WithTLSConfig(cfg),
		dot.WithServerName("127.0.0.1"),
		dot.WithTimeout(2*time.Second),
	)
	require.NoError(t, err)

	q, _ := dnsmsg.NewBuilder().
		ID(0x9999).
		Question(dnsmsg.NewQuestion(dnsname.MustParse("example.com"), rrtype.A)).
		Build()

	se, ok := ex.(transport.StreamExchanger)
	require.True(t, ok)
	stream, err := se.Stream(t.Context(), q)
	require.NoError(t, err)
	defer stream.Close()
	resp, err := stream.Next(t.Context())
	require.NoError(t, err)
	require.Equal(t, q.ID(), resp.ID())
}
