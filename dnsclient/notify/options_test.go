package notify_test

import (
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient/notify"
	"github.com/lestrrat-go/acidns/dnsclient/transport/udp"
	"github.com/lestrrat-go/acidns/dnsclient/transport"
	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/lestrrat-go/acidns/dnsserver"
	"github.com/stretchr/testify/require"
)

func TestSendWithSOAAndTimeout(t *testing.T) {
	t.Parallel()

	var got atomic.Pointer[dnsmsg.Question]
	addr := startSecondary(t, func(q dnsmsg.Question, _ dnsserver.ResponseWriter) {
		got.Store(&q)
	})
	ex, err := udp.New(addr)
	require.NoError(t, err)

	soa := rdata.NewSOA(
		dnsname.MustParse("ns1.example.com"),
		dnsname.MustParse("hm.example.com"),
		42, time.Hour, time.Hour, time.Hour, time.Hour,
	)

	resp, err := notify.Send(t.Context(), ex, dnsname.MustParse("example.com"),
		notify.WithSOA(soa),
		notify.WithTimeout(2*time.Second),
	)
	require.NoError(t, err)
	require.Equal(t, dnsmsg.OpcodeNotify, resp.Flags().Opcode())
}

func TestBroadcast(t *testing.T) {
	t.Parallel()

	addrs := []netip.AddrPort{
		startSecondary(t, nil),
		startSecondary(t, nil),
	}
	exs := make([]transport.Exchanger, len(addrs))
	for i, a := range addrs {
		ex, err := udp.New(a)
		require.NoError(t, err)
		exs[i] = ex
	}

	results := notify.Broadcast(t.Context(), exs, dnsname.MustParse("example.com"))
	require.Len(t, results, 2)
	for _, r := range results {
		require.NoError(t, r.Err())
		require.NotNil(t, r.Response())
		require.NotNil(t, r.Exchanger())
	}
}
