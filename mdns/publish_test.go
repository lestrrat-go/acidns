package mdns_test

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/mdns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// fakeTransport records every Send and lets tests feed canned responses
// to Recv.
type fakeTransport struct {
	mu    sync.Mutex
	sent  []wire.Message
	inbox chan wire.Message
}

func newFakeTransport() *fakeTransport {
	return &fakeTransport{inbox: make(chan wire.Message, 16)}
}

func (t *fakeTransport) Send(m wire.Message) error {
	t.mu.Lock()
	t.sent = append(t.sent, m)
	t.mu.Unlock()
	return nil
}

func (t *fakeTransport) Recv(ctx context.Context) (wire.Message, error) {
	select {
	case m := <-t.inbox:
		return m, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (t *fakeTransport) sentCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.sent)
}

func samplePublication() mdns.Publication {
	return mdns.Publication{
		Instance: wire.MustParseName("Living Room TV._http._tcp.local."),
		Type:     wire.MustParseName("_http._tcp.local."),
		Host:     wire.MustParseName("tv-living-room.local."),
		Port:     8080,
		Addrs:    []netip.Addr{netip.MustParseAddr("192.0.2.10")},
		Text:     map[string]string{"path": "/"},
		TTL:      120 * time.Second,
	}
}

func TestAnnounceProbeThenAnnounce(t *testing.T) {
	t.Parallel()
	tr := newFakeTransport()
	a, err := mdns.NewAnnouncer(
		mdns.WithAnnouncerTransport(tr),
		mdns.WithProbeTiming(time.Millisecond, 3),
		mdns.WithAnnounceTiming(time.Millisecond, 2),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	require.NoError(t, a.Announce(ctx, samplePublication()))

	// Should have 3 probes + 2 announcements = 5 messages.
	require.Equal(t, 5, tr.sentCount())
}

func TestAnnounceConflictAborts(t *testing.T) {
	t.Parallel()
	tr := newFakeTransport()
	a, err := mdns.NewAnnouncer(
		mdns.WithAnnouncerTransport(tr),
		mdns.WithProbeTiming(50*time.Millisecond, 3),
		mdns.WithAnnounceTiming(time.Millisecond, 2),
	)
	require.NoError(t, err)

	// Inject a conflicting answer: someone else owns Host with a
	// different address.
	conflict, _ := wire.NewBuilder().
		Response(true).
		Authoritative(true).
		Answer(wire.NewRecord(wire.MustParseName("tv-living-room.local."),
			120*time.Second,
			rdata.NewA(netip.MustParseAddr("192.0.2.99")))).
		Build()
	tr.inbox <- conflict

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	err = a.Announce(ctx, samplePublication())
	require.ErrorIs(t, err, mdns.ErrConflict)
}

func TestAnnouncementSetsCacheFlushBit(t *testing.T) {
	t.Parallel()
	tr := newFakeTransport()
	a, err := mdns.NewAnnouncer(
		mdns.WithAnnouncerTransport(tr),
		mdns.WithProbeTiming(time.Millisecond, 1),
		mdns.WithAnnounceTiming(time.Millisecond, 1),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	require.NoError(t, a.Announce(ctx, samplePublication()))

	// Last sent message is the announcement. Inspect SRV / A class fields.
	tr.mu.Lock()
	defer tr.mu.Unlock()
	last := tr.sent[len(tr.sent)-1]
	var srvSeen, aSeen bool
	for _, r := range last.Answers() {
		c := uint16(r.Class())
		switch r.Type() {
		case rrtype.SRV:
			srvSeen = true
			require.True(t, c&mdns.CacheFlushBit != 0, "SRV missing cache-flush bit")
		case rrtype.A:
			aSeen = true
			require.True(t, c&mdns.CacheFlushBit != 0, "A missing cache-flush bit")
		case rrtype.PTR:
			// PTR is shared-set; must NOT have flush bit.
			require.True(t, c&mdns.CacheFlushBit == 0, "PTR set cache-flush bit")
		}
	}
	require.True(t, srvSeen)
	require.True(t, aSeen)
}

func TestWithdrawSendsTTLZero(t *testing.T) {
	t.Parallel()
	tr := newFakeTransport()
	a, err := mdns.NewAnnouncer(
		mdns.WithAnnouncerTransport(tr),
		mdns.WithProbeTiming(time.Millisecond, 1),
		mdns.WithAnnounceTiming(time.Millisecond, 1),
	)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	require.NoError(t, a.Announce(ctx, samplePublication()))
	beforeWithdraw := tr.sentCount()
	require.NoError(t, a.Withdraw(ctx))
	require.Equal(t, beforeWithdraw+1, tr.sentCount())

	// Inspect the goodbye: every record TTL must be 0.
	tr.mu.Lock()
	defer tr.mu.Unlock()
	bye := tr.sent[len(tr.sent)-1]
	for _, r := range bye.Answers() {
		require.Equal(t, time.Duration(0), r.TTL(), "expected TTL=0 in goodbye")
	}
}

func TestWithdrawWithoutAnnounceNoOp(t *testing.T) {
	t.Parallel()
	tr := newFakeTransport()
	a, err := mdns.NewAnnouncer(mdns.WithAnnouncerTransport(tr))
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	require.NoError(t, a.Withdraw(ctx))
	require.Equal(t, 0, tr.sentCount())
}
