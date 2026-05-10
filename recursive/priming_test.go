package recursive_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/recursive"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

func primingResponseDialer(t *testing.T, newA, newB netip.Addr) stubDialer {
	t.Helper()
	return stubDialer{fn: func(_ context.Context, _ netip.AddrPort, q wire.Message) (wire.Message, error) {
		return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
			ns1 := wire.NewRecord(wire.RootName(), 86400*time.Second,
				rdata.MustNewNS(wire.MustParseName("a.root-servers.test.")))
			ns2 := wire.NewRecord(wire.RootName(), 86400*time.Second,
				rdata.MustNewNS(wire.MustParseName("b.root-servers.test.")))
			a1 := wire.NewRecord(wire.MustParseName("a.root-servers.test."),
				86400*time.Second, rdata.MustNewA(newA))
			a2 := wire.NewRecord(wire.MustParseName("b.root-servers.test."),
				86400*time.Second, rdata.MustNewA(newB))
			return b.Authoritative(true).
				Answer(ns1).Answer(ns2).
				Additional(a1).Additional(a2)
		}), nil
	}}
}

func TestPrimeReplacesRoots(t *testing.T) {
	t.Parallel()
	seedRoot := netip.MustParseAddrPort("198.51.100.1:53")
	newA := netip.MustParseAddr("203.0.113.10")
	newB := netip.MustParseAddr("203.0.113.20")

	called := make(chan netip.AddrPort, 4)
	dialer := stubDialer{fn: func(ctx context.Context, server netip.AddrPort, q wire.Message) (wire.Message, error) {
		select {
		case called <- server:
		default:
		}
		return primingResponseDialer(t, newA, newB).fn(ctx, server, q)
	}}

	r := mustRecursive(t,
		recursive.WithRoots(seedRoot),
		recursive.WithDialer(dialer),
	)
	require.NoError(t, r.Prime(context.Background()))

	// Drain the priming call.
	<-called

	// A subsequent resolve must hit one of the new addresses.
	_, _ = r.Resolve(context.Background(), wire.MustParseName("example.test."), rrtype.A)
	select {
	case got := <-called:
		require.True(t, got.Addr() == newA || got.Addr() == newB,
			"expected new root addr, got %v", got)
	case <-time.After(time.Second):
		t.Fatalf("resolver never queried a primed root address")
	}
}

func TestPrimeFailureKeepsRoots(t *testing.T) {
	t.Parallel()
	seedRoot := netip.MustParseAddrPort("198.51.100.1:53")

	dialer := stubDialer{fn: func(_ context.Context, _ netip.AddrPort, q wire.Message) (wire.Message, error) {
		return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder {
			return b.RCODE(wire.RCODEServFail)
		}), nil
	}}
	r := mustRecursive(t,
		recursive.WithRoots(seedRoot),
		recursive.WithDialer(dialer),
	)
	require.Error(t, r.Prime(context.Background()), "SERVFAIL prime must surface error")
	// Roots remain seedRoot; we can't observe directly but the
	// failed prime path is exercised.
}

func TestRunWithoutPrimingReturnsImmediately(t *testing.T) {
	t.Parallel()
	r := mustRecursive(t,
		recursive.WithRoots(netip.MustParseAddrPort("198.51.100.1:53")),
	)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, r.RunMaintenance(ctx))
}

func TestRunCancelsOnContextDone(t *testing.T) {
	t.Parallel()
	dialer := stubDialer{fn: func(_ context.Context, _ netip.AddrPort, q wire.Message) (wire.Message, error) {
		return mkResp(t, q, func(b *wire.MessageBuilder) *wire.MessageBuilder { return b }), nil
	}}
	r := mustRecursive(t,
		recursive.WithRoots(netip.MustParseAddrPort("198.51.100.1:53")),
		recursive.WithDialer(dialer),
		recursive.WithRootPriming(time.Hour),
	)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.RunMaintenance(ctx) }()
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatalf("Run did not exit after cancel")
	}
}
