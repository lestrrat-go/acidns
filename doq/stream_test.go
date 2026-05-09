//go:build !acidns_no_doq

package doq_test

import (
	"context"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/doq"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

func TestDoQStream(t *testing.T) {
	t.Parallel()
	addr, cfg := startDoQ(t)
	ex, err := doq.New(addr,
		doq.WithTLSConfig(cfg),
		doq.WithTimeout(2*time.Second),
		doq.WithServerName("127.0.0.1"),
	)
	require.NoError(t, err)

	q, _ := wire.NewMessageBuilder().
		ID(0xa1b2).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()

	se, ok := ex.(acidns.StreamExchanger)
	require.True(t, ok)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	stream, err := se.Stream(ctx, q)
	require.NoError(t, err)
	defer func() { _ = stream.Close() }()
	resp, err := stream.Next(ctx)
	require.NoError(t, err)
	require.Equal(t, q.ID(), resp.ID())
}
