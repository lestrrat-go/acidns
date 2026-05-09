package notify_test

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/notify"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/stretchr/testify/require"
)

func TestSendWithSOAAndTimeout(t *testing.T) {
	t.Parallel()

	var got atomic.Pointer[wire.Question]
	addr := startSecondary(t, func(_ context.Context, q wire.Question, _ acidns.ResponseWriter) {
		got.Store(&q)
	})
	ex, err := acidns.NewUDPExchanger(addr)
	require.NoError(t, err)

	soa := rdata.MustNewSOA(
		wire.MustParseName("ns1.example.com"),
		wire.MustParseName("hm.example.com"),
		42, time.Hour, time.Hour, time.Hour, time.Hour,
	)

	resp, err := notify.Send(t.Context(), ex, wire.MustParseName("example.com"),
		notify.WithSOA(soa),
		notify.WithTimeout(2*time.Second),
	)
	require.NoError(t, err)
	require.Equal(t, wire.OpcodeNotify, resp.Flags().Opcode())
}

func TestBroadcast(t *testing.T) {
	t.Parallel()

	addrs := []netip.AddrPort{
		startSecondary(t, nil),
		startSecondary(t, nil),
	}
	exs := make([]acidns.Exchanger, len(addrs))
	for i, a := range addrs {
		ex, err := acidns.NewUDPExchanger(a)
		require.NoError(t, err)
		exs[i] = ex
	}

	results := notify.Broadcast(t.Context(), exs, wire.MustParseName("example.com"))
	require.Len(t, results, 2)
	for _, r := range results {
		require.NoError(t, r.Err())
		require.NotNil(t, r.Response())
		require.NotNil(t, r.Exchanger())
	}
}
