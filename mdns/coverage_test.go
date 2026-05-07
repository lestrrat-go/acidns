package mdns_test

import (
	"context"
	"errors"
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

// errorTransport always returns sendErr from Send and recvErr from Recv.
type errorTransport struct {
	sendErr error
	recvErr error
	mu      sync.Mutex
	sentN   int
	failOn  int // 0 = always; >0 = succeed first N-1 then fail
}

func (e *errorTransport) Send(m wire.Message) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sentN++
	if e.sendErr == nil {
		return nil
	}
	if e.failOn > 0 && e.sentN < e.failOn {
		return nil
	}
	return e.sendErr
}

func (e *errorTransport) Recv(ctx context.Context) (wire.Message, error) {
	if e.recvErr != nil {
		return nil, e.recvErr
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestNewAnnouncerRequiresTransport(t *testing.T) {
	t.Parallel()
	a, err := mdns.NewAnnouncer()
	require.Error(t, err)
	require.Nil(t, a)
}

func TestWithAnnouncerClock(t *testing.T) {
	t.Parallel()
	tr := newFakeTransport()
	called := false
	clk := func() time.Time {
		called = true
		return time.Unix(0, 0)
	}
	a, err := mdns.NewAnnouncer(
		mdns.WithAnnouncerTransport(tr),
		mdns.WithAnnouncerClock(clk),
		mdns.WithProbeTiming(time.Millisecond, 1),
		mdns.WithAnnounceTiming(time.Millisecond, 1),
	)
	require.NoError(t, err)
	require.NoError(t, a.Announce(t.Context(), samplePublication()))
	// The clock currently isn't called inside Announce — but the
	// option still has to wire it into config without error.
	_ = called
}

func TestAnnounceDefaultTTL(t *testing.T) {
	t.Parallel()
	tr := newFakeTransport()
	a, err := mdns.NewAnnouncer(
		mdns.WithAnnouncerTransport(tr),
		mdns.WithProbeTiming(time.Millisecond, 1),
		mdns.WithAnnounceTiming(time.Millisecond, 1),
	)
	require.NoError(t, err)

	p := samplePublication()
	p.TTL = 0 // exercise default branch
	require.NoError(t, a.Announce(t.Context(), p))
}

func TestAnnounceIncompletePublication(t *testing.T) {
	t.Parallel()
	tr := newFakeTransport()
	a, err := mdns.NewAnnouncer(mdns.WithAnnouncerTransport(tr))
	require.NoError(t, err)

	// Missing Host.
	p := mdns.Publication{
		Instance: wire.MustParseName("Foo._http._tcp.local."),
		Type:     wire.MustParseName("_http._tcp.local."),
	}
	err = a.Announce(t.Context(), p)
	require.Error(t, err)
	require.Equal(t, 0, tr.sentCount())
}

func TestAnnounceProbeSendError(t *testing.T) {
	t.Parallel()
	tr := &errorTransport{sendErr: errors.New("nope")}
	a, err := mdns.NewAnnouncer(
		mdns.WithAnnouncerTransport(tr),
		mdns.WithProbeTiming(time.Millisecond, 3),
	)
	require.NoError(t, err)

	err = a.Announce(t.Context(), samplePublication())
	require.Error(t, err)
}

func TestAnnounceAnnouncementSendError(t *testing.T) {
	t.Parallel()
	// Probes succeed (1 probe), the announcement send fails.
	tr := &errorTransport{sendErr: errors.New("nope"), failOn: 2}
	a, err := mdns.NewAnnouncer(
		mdns.WithAnnouncerTransport(tr),
		mdns.WithProbeTiming(time.Millisecond, 1),
		mdns.WithAnnounceTiming(time.Millisecond, 1),
	)
	require.NoError(t, err)

	err = a.Announce(t.Context(), samplePublication())
	require.Error(t, err)
}

func TestAnnounceCancelDuringAnnounceWait(t *testing.T) {
	t.Parallel()
	tr := newFakeTransport()
	a, err := mdns.NewAnnouncer(
		mdns.WithAnnouncerTransport(tr),
		mdns.WithProbeTiming(time.Millisecond, 1),
		// 5s announce wait — we'll cancel before it elapses.
		mdns.WithAnnounceTiming(5*time.Second, 3),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	err = a.Announce(ctx, samplePublication())
	require.ErrorIs(t, err, context.Canceled)
}

// recvErrTransport returns a non-context error from Recv so we can
// exercise the listenForConflict err-return path.
type recvErrTransport struct {
	mu    sync.Mutex
	sent  int
	recvE error
}

func (r *recvErrTransport) Send(m wire.Message) error {
	r.mu.Lock()
	r.sent++
	r.mu.Unlock()
	return nil
}

func (r *recvErrTransport) Recv(ctx context.Context) (wire.Message, error) {
	return nil, r.recvE
}

func TestAnnounceListenRecvError(t *testing.T) {
	t.Parallel()
	tr := &recvErrTransport{recvE: errors.New("transport boom")}
	a, err := mdns.NewAnnouncer(
		mdns.WithAnnouncerTransport(tr),
		mdns.WithProbeTiming(50*time.Millisecond, 3),
	)
	require.NoError(t, err)
	err = a.Announce(t.Context(), samplePublication())
	require.Error(t, err)
}

func TestWithdrawSendError(t *testing.T) {
	t.Parallel()
	// Use error transport that succeeds for probe + announce, fails for goodbye.
	tr := &errorTransport{sendErr: errors.New("bye fail"), failOn: 4}
	a, err := mdns.NewAnnouncer(
		mdns.WithAnnouncerTransport(tr),
		mdns.WithProbeTiming(time.Millisecond, 2),
		mdns.WithAnnounceTiming(time.Millisecond, 1),
	)
	require.NoError(t, err)
	require.NoError(t, a.Announce(t.Context(), samplePublication()))
	err = a.Withdraw(t.Context())
	require.Error(t, err)
}

func TestConflictsWithSRVBranches(t *testing.T) {
	t.Parallel()

	// Conflicting SRV: same Instance, different Target.
	tr := newFakeTransport()
	a, err := mdns.NewAnnouncer(
		mdns.WithAnnouncerTransport(tr),
		mdns.WithProbeTiming(50*time.Millisecond, 3),
		mdns.WithAnnounceTiming(time.Millisecond, 1),
	)
	require.NoError(t, err)

	conflict, _ := wire.NewBuilder().
		Response(true).
		Authoritative(true).
		Answer(wire.NewRecord(
			wire.MustParseName("Living Room TV._http._tcp.local."),
			120*time.Second,
			rdata.NewSRV(0, 0, 8080, wire.MustParseName("intruder.local.")))).
		Build()
	tr.inbox <- conflict

	err = a.Announce(t.Context(), samplePublication())
	require.ErrorIs(t, err, mdns.ErrConflict)
}

func TestConflictsWithSRVNonconflicting(t *testing.T) {
	t.Parallel()

	tr := newFakeTransport()
	a, err := mdns.NewAnnouncer(
		mdns.WithAnnouncerTransport(tr),
		mdns.WithProbeTiming(20*time.Millisecond, 2),
		mdns.WithAnnounceTiming(time.Millisecond, 1),
	)
	require.NoError(t, err)

	// Same Instance, same target+port — NOT a conflict.
	matching, _ := wire.NewBuilder().
		Response(true).
		Authoritative(true).
		Answer(wire.NewRecord(
			wire.MustParseName("Living Room TV._http._tcp.local."),
			120*time.Second,
			rdata.NewSRV(0, 0, 8080, wire.MustParseName("tv-living-room.local.")))).
		// Unrelated PTR (ignored by conflict detector).
		Answer(wire.NewRecord(
			wire.MustParseName("_http._tcp.local."),
			120*time.Second,
			rdata.NewPTR(wire.MustParseName("Other._http._tcp.local.")))).
		// SRV with a different owner name (ignored).
		Answer(wire.NewRecord(
			wire.MustParseName("Other._http._tcp.local."),
			120*time.Second,
			rdata.NewSRV(0, 0, 1234, wire.MustParseName("other.local.")))).
		Build()
	tr.inbox <- matching

	require.NoError(t, a.Announce(t.Context(), samplePublication()))
}

func TestConflictsWithAAAA(t *testing.T) {
	t.Parallel()

	tr := newFakeTransport()
	a, err := mdns.NewAnnouncer(
		mdns.WithAnnouncerTransport(tr),
		mdns.WithProbeTiming(50*time.Millisecond, 3),
		mdns.WithAnnounceTiming(time.Millisecond, 1),
	)
	require.NoError(t, err)

	// AAAA at the host name with an address we don't own.
	conflict, _ := wire.NewBuilder().
		Response(true).
		Authoritative(true).
		Answer(wire.NewRecord(
			wire.MustParseName("tv-living-room.local."),
			120*time.Second,
			rdata.NewAAAA(netip.MustParseAddr("2001:db8::1")))).
		Build()
	tr.inbox <- conflict

	p := samplePublication()
	p.Addrs = []netip.Addr{netip.MustParseAddr("192.0.2.10")} // IPv4 only
	err = a.Announce(t.Context(), p)
	require.ErrorIs(t, err, mdns.ErrConflict)
}

func TestConflictsWithAAAANonconflicting(t *testing.T) {
	t.Parallel()

	tr := newFakeTransport()
	a, err := mdns.NewAnnouncer(
		mdns.WithAnnouncerTransport(tr),
		mdns.WithProbeTiming(20*time.Millisecond, 2),
		mdns.WithAnnounceTiming(time.Millisecond, 1),
	)
	require.NoError(t, err)

	v6 := netip.MustParseAddr("2001:db8::1")
	matching, _ := wire.NewBuilder().
		Response(true).
		Authoritative(true).
		Answer(wire.NewRecord(
			wire.MustParseName("tv-living-room.local."),
			120*time.Second,
			rdata.NewAAAA(v6))).
		// AAAA at a different name (skipped).
		Answer(wire.NewRecord(
			wire.MustParseName("other.local."),
			120*time.Second,
			rdata.NewAAAA(netip.MustParseAddr("2001:db8::99")))).
		// A at a different name (skipped via name mismatch).
		Answer(wire.NewRecord(
			wire.MustParseName("other.local."),
			120*time.Second,
			rdata.NewA(netip.MustParseAddr("198.51.100.5")))).
		Build()
	tr.inbox <- matching

	p := samplePublication()
	p.Addrs = []netip.Addr{netip.MustParseAddr("192.0.2.10"), v6}
	require.NoError(t, a.Announce(t.Context(), p))
}

func TestPublicationRecordsIPv6(t *testing.T) {
	t.Parallel()
	tr := newFakeTransport()
	a, err := mdns.NewAnnouncer(
		mdns.WithAnnouncerTransport(tr),
		mdns.WithProbeTiming(time.Millisecond, 1),
		mdns.WithAnnounceTiming(time.Millisecond, 1),
	)
	require.NoError(t, err)

	p := samplePublication()
	p.Addrs = []netip.Addr{netip.MustParseAddr("2001:db8::42")}
	require.NoError(t, a.Announce(t.Context(), p))

	tr.mu.Lock()
	defer tr.mu.Unlock()
	last := tr.sent[len(tr.sent)-1]
	var sawAAAA bool
	for _, r := range last.Answers() {
		if r.Type() == rrtype.AAAA {
			sawAAAA = true
			require.Equal(t, "2001:db8::42", r.RData().(rdata.AAAA).Addr().String())
		}
	}
	require.True(t, sawAAAA)
}

func TestPublicationRecordsNoText(t *testing.T) {
	t.Parallel()
	tr := newFakeTransport()
	a, err := mdns.NewAnnouncer(
		mdns.WithAnnouncerTransport(tr),
		mdns.WithProbeTiming(time.Millisecond, 1),
		mdns.WithAnnounceTiming(time.Millisecond, 1),
	)
	require.NoError(t, err)

	p := samplePublication()
	p.Text = nil // exercise zero-text branch
	require.NoError(t, a.Announce(t.Context(), p))

	tr.mu.Lock()
	defer tr.mu.Unlock()
	last := tr.sent[len(tr.sent)-1]
	for _, r := range last.Answers() {
		require.NotEqual(t, rrtype.TXT, r.Type(), "expected no TXT in publication when Text is empty")
	}
}

func TestParseBrowseResponsePTRWithoutSRV(t *testing.T) {
	t.Parallel()
	svcType := wire.MustParseName("_http._tcp.local")
	instance := wire.MustParseName("Lonely._http._tcp.local")
	resp, err := wire.NewBuilder().
		ID(0).
		Response(true).
		// PTR but no matching SRV → service should be skipped.
		Answer(wire.NewRecord(svcType, time.Minute, rdata.NewPTR(instance))).
		Build()
	require.NoError(t, err)

	require.Equal(t, 0, len(mdns.ParseBrowseResponse(resp)))
}

func TestParseBrowseResponseAAAAFromAdditional(t *testing.T) {
	t.Parallel()
	svcType := wire.MustParseName("_http._tcp.local")
	instance := wire.MustParseName("V6._http._tcp.local")
	host := wire.MustParseName("v6.local")

	srv := rdata.NewSRV(0, 0, 8080, host)
	v6 := rdata.NewAAAA(netip.MustParseAddr("2001:db8::1"))

	resp, err := wire.NewBuilder().
		ID(0).
		Response(true).
		Answer(wire.NewRecord(svcType, time.Minute, rdata.NewPTR(instance))).
		Answer(wire.NewRecord(instance, time.Minute, srv)).
		// AAAA in additional section.
		Additional(wire.NewRecord(host, time.Minute, v6)).
		Build()
	require.NoError(t, err)

	services := mdns.ParseBrowseResponse(resp)
	require.Equal(t, 1, len(services))
	require.Equal(t, "2001:db8::1", services[0].Addrs[0].String())
}

func TestParseTXTBareKeyAndEmpty(t *testing.T) {
	t.Parallel()
	// Use Browse-flavoured response carrying a TXT with bare-key + empty
	// + key=value. parseTXT is exercised via ParseBrowseResponse.
	svcType := wire.MustParseName("_http._tcp.local")
	instance := wire.MustParseName("BareKey._http._tcp.local")
	host := wire.MustParseName("barekey.local")

	srv := rdata.NewSRV(0, 0, 80, host)
	txt, err := rdata.NewTXT("flag", "key=value", "")
	require.NoError(t, err)

	resp, err := wire.NewBuilder().
		ID(0).
		Response(true).
		Answer(wire.NewRecord(svcType, time.Minute, rdata.NewPTR(instance))).
		Answer(wire.NewRecord(instance, time.Minute, srv)).
		Answer(wire.NewRecord(instance, time.Minute, txt)).
		Build()
	require.NoError(t, err)

	services := mdns.ParseBrowseResponse(resp)
	require.Equal(t, 1, len(services))
	require.Equal(t, "", services[0].Text["flag"])    // bare key
	require.Equal(t, "value", services[0].Text["key"]) // key=value
	_, hasEmpty := services[0].Text[""]
	require.False(t, hasEmpty, "empty TXT string should be ignored")
}
