package acidns_test

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/resolvconf"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// pollDropCounter polls fn until it returns a non-zero value or the
// deadline elapses. Drop counters are incremented after the listener
// processes a packet, so a single Write+small-sleep isn't deterministic
// across schedulers.
func pollDropCounter(t *testing.T, fn func() uint64) uint64 {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if v := fn(); v > 0 {
			return v
		}
		time.Sleep(5 * time.Millisecond)
	}
	return fn()
}

// TestUDPControllerCountsParseErrors fires a deliberately-truncated
// datagram at the listener and watches PacketsDroppedParseError tick.
// This is the canonical "garbage at the wire" attack signal — under
// real spoofing floods the counter rises in lockstep with the noise.
func TestUDPControllerCountsParseErrors(t *testing.T) {
	t.Parallel()
	srv, err := acidns.NewUDPServer(netip.MustParseAddrPort("127.0.0.1:0"), echoHandler{})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)
	require.NoError(t, err)

	conn, err := net.Dial("udp", ctrl.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	// Send a 3-byte payload — too short for a DNS header (12 bytes).
	_, err = conn.Write([]byte{0xff, 0xff, 0xff})
	require.NoError(t, err)

	require.Positive(t, pollDropCounter(t, ctrl.PacketsDroppedParseError),
		"a truncated datagram must increment the parse-error counter")
}

// TestUDPControllerCountsPreflightDrops fires a spoofed *response*
// (QR=1) at the listener. Preflight rejects responses (they're a
// reflection-attack participation primitive) and increments
// PacketsDroppedByPreflight.
func TestUDPControllerCountsPreflightDrops(t *testing.T) {
	t.Parallel()
	srv, err := acidns.NewUDPServer(netip.MustParseAddrPort("127.0.0.1:0"), echoHandler{})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)
	require.NoError(t, err)

	// Build a well-formed wire message with QR=1 (a response masquerading
	// as a query). Preflight refuses these.
	m, err := wire.NewMessageBuilder().
		ID(0x4242).
		Response(true).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	require.NoError(t, err)
	buf, err := wire.Pack(m)
	require.NoError(t, err)

	conn, err := net.Dial("udp", ctrl.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	_, err = conn.Write(buf)
	require.NoError(t, err)

	require.Positive(t, pollDropCounter(t, ctrl.PacketsDroppedByPreflight),
		"a QR=1 spoofed response must increment the preflight counter")
}

// TestUDPControllerCountsPreFilterDrops wires up a PreParseFilter that
// denies every source and verifies the dropped-by-pre-filter counter
// rises when traffic arrives. Operator-supplied deny-lists rely on this
// counter to confirm they're effective.
func TestUDPControllerCountsPreFilterDrops(t *testing.T) {
	t.Parallel()
	denyAll := func(_ netip.AddrPort) bool { return false }
	srv, err := acidns.NewUDPServer(netip.MustParseAddrPort("127.0.0.1:0"), echoHandler{},
		acidns.WithUDPListenerPreParseFilter(denyAll),
	)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)
	require.NoError(t, err)

	q, err := wire.NewMessageBuilder().
		ID(0xbeef).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	require.NoError(t, err)
	buf, err := wire.Pack(q)
	require.NoError(t, err)

	conn, err := net.Dial("udp", ctrl.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	_, err = conn.Write(buf)
	require.NoError(t, err)

	require.Positive(t, pollDropCounter(t, ctrl.PacketsDroppedByPreFilter),
		"a deny-all pre-filter must drop the inbound packet")
}

// TestUDPControllerCountsAtSemaphore wires a single-slot inflight
// semaphore and a slow handler, then fires multiple queries
// back-to-back. The first one occupies the semaphore; subsequent
// packets are refused at the cap and the inflight-drops counter ticks.
func TestUDPControllerCountsAtSemaphore(t *testing.T) {
	t.Parallel()
	// Handler that blocks until released so the inflight slot stays
	// occupied for the duration of the test.
	released := make(chan struct{})
	t.Cleanup(func() { close(released) })
	var entered sync.Once
	enterCh := make(chan struct{})
	slow := acidns.HandlerFunc(func(_ context.Context, w acidns.ResponseWriter, q wire.Message) {
		entered.Do(func() { close(enterCh) })
		<-released
		resp, _ := wire.NewMessageBuilder().ID(q.ID()).Response(true).
			Question(q.Questions()[0]).Build()
		_ = w.WriteMsg(resp)
	})

	srv, err := acidns.NewUDPServer(netip.MustParseAddrPort("127.0.0.1:0"), slow,
		acidns.WithUDPListenerMaxInflight(1),
	)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)
	require.NoError(t, err)

	q, err := wire.NewMessageBuilder().
		ID(0x1).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	require.NoError(t, err)
	buf, err := wire.Pack(q)
	require.NoError(t, err)

	conn, err := net.Dial("udp", ctrl.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	// First packet → admitted, occupies the only inflight slot.
	_, err = conn.Write(buf)
	require.NoError(t, err)
	select {
	case <-enterCh:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not start within deadline")
	}
	// Subsequent packets while the slot is busy → dropped at semaphore.
	for range 5 {
		_, err = conn.Write(buf)
		require.NoError(t, err)
	}

	require.Positive(t, pollDropCounter(t, ctrl.PacketsDroppedAtSemaphore),
		"packets arriving while inflight is full must be dropped at the semaphore")
}

// TestUDPListenerWriteTimeoutAccepted is construction-only — exercising
// the write-deadline behaviour deterministically requires blocking the
// kernel's outbound UDP buffer, which is hard from a portable test. The
// option's wiring into [acidns.NewUDPServer] is still validated here.
func TestUDPListenerWriteTimeoutAccepted(t *testing.T) {
	t.Parallel()
	srv, err := acidns.NewUDPServer(netip.MustParseAddrPort("127.0.0.1:0"), echoHandler{},
		acidns.WithUDPListenerWriteTimeout(2*time.Second),
	)
	require.NoError(t, err)
	require.NotNil(t, srv)
}

// TestTCPListenerMaxQueriesPerConnCloses: with the cap set to 1 the
// server must close the connection after a single query, so a second
// pipelined query on the same TCP connection observes EOF.
func TestTCPListenerMaxQueriesPerConnCloses(t *testing.T) {
	t.Parallel()
	srv, err := acidns.NewTCPServer(netip.MustParseAddrPort("127.0.0.1:0"), echoHandler{},
		acidns.WithTCPListenerMaxQueriesPerConn(1),
	)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)
	require.NoError(t, err)

	conn, err := net.Dial("tcp", ctrl.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	// First query → admitted.
	q, _ := wire.NewMessageBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	buf, _ := wire.Pack(q)
	require.NoError(t, conn.SetDeadline(time.Now().Add(2*time.Second)))
	hdr := []byte{byte(len(buf) >> 8), byte(len(buf))}
	_, err = conn.Write(append(hdr, buf...))
	require.NoError(t, err)
	// Drain the first response so we know the server has handled the cap.
	respHdr := make([]byte, 2)
	_, err = conn.Read(respHdr)
	require.NoError(t, err)
	respLen := int(respHdr[0])<<8 | int(respHdr[1])
	respBody := make([]byte, respLen)
	_, err = conn.Read(respBody)
	require.NoError(t, err)

	// Second query on the same connection: the server has already hit
	// the cap and closed the conn. Either Write succeeds and Read
	// returns EOF, or Write itself fails. Either way the second
	// request never gets a response.
	_, _ = conn.Write(append(hdr, buf...))
	_, err = conn.Read(respHdr)
	require.Error(t, err, "after WithTCPListenerMaxQueriesPerConn(1) the second query must observe a closed conn")
}

// TestTCPListenerOptionsRoundTripAccepted covers the remaining TCP
// options whose saturation behaviour is hard to drive in unit tests
// (WriteTimeout needs a wedged kernel buffer; MaxConnLifetime takes
// minutes; MaxInflightPerConn needs many concurrent in-flight queries
// on one connection). Construction + a happy-path exchange suffices to
// guarantee the options don't break the listener.
func TestTCPListenerOptionsRoundTripAccepted(t *testing.T) {
	t.Parallel()
	srv, err := acidns.NewTCPServer(netip.MustParseAddrPort("127.0.0.1:0"), echoHandler{},
		acidns.WithTCPListenerWriteTimeout(3*time.Second),
		acidns.WithTCPListenerMaxConnLifetime(30*time.Minute),
		acidns.WithTCPListenerMaxInflightPerConn(16),
	)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)
	require.NoError(t, err)

	ex, err := acidns.NewTCPClient(ctrl.Addr())
	require.NoError(t, err)
	q, _ := wire.NewMessageBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	resp, err := ex.Exchange(ctx, q)
	require.NoError(t, err)
	require.Equal(t, uint16(1), resp.ID())
}

// TestResolverWithCaseRandomizationFalse pins that the option is wired
// into NewResolver and does not conflict with the WithServers path.
// Driving the 0x20 propagation past the UDP exchanger requires
// intercepting the outbound wire bytes — a level of plumbing better
// suited to the exchanger-level test in exchanger_udp_caserand_test.go.
func TestResolverWithCaseRandomizationFalse(t *testing.T) {
	t.Parallel()
	r, err := acidns.NewResolver(
		acidns.WithServers(netip.MustParseAddrPort("127.0.0.1:53")),
		acidns.WithCaseRandomization(false),
	)
	require.NoError(t, err)
	require.NotNil(t, r)
}

// TestResolverWithCaseRandomizationConflictsWithExchanger pins the
// constructor's rejection of WithCaseRandomization + WithExchanger.
// The check ensures a caller-built exchanger isn't silently overridden
// by an option that no longer takes effect.
func TestResolverWithCaseRandomizationConflictsWithExchanger(t *testing.T) {
	t.Parallel()
	ex, err := acidns.NewUDPClient(netip.MustParseAddrPort("127.0.0.1:53"))
	require.NoError(t, err)
	_, err = acidns.NewResolver(
		acidns.WithExchanger(ex),
		acidns.WithCaseRandomization(false),
	)
	require.Error(t, err, "WithCaseRandomization + WithExchanger must conflict")
}

// TestNewSystemResolver covers the zero-config entry point. The wrapper
// is a thin layer over NewResolver(append(opts, WithSystemResolvers())...)
// so its behaviour is determined by whether the host has a usable
// /etc/resolv.conf — we branch on that fact instead of silently passing
// either way.
func TestNewSystemResolver(t *testing.T) {
	t.Parallel()
	cfg, loadErr := resolvconf.Load("")
	systemUsable := loadErr == nil && len(cfg.Nameservers()) > 0

	r, err := acidns.NewSystemResolver()
	if systemUsable {
		require.NoError(t, err)
		require.NotNil(t, r)
		require.Implements(t, (*acidns.SearchListProvider)(nil), r,
			"the system resolver carries the resolv.conf search list")
	} else {
		require.Error(t, err, "NewSystemResolver must surface the missing-/empty-resolv.conf error")
		require.Nil(t, r)
	}
}

// TestCookieClockInjected proves WithCookieClock actually overrides the
// clock the cookies middleware uses. The middleware consults its clock
// on every cookie-bearing query (to evaluate freshness and mint a
// server cookie), so a query carrying a client cookie exercises the
// injection path.
func TestCookieClockInjected(t *testing.T) {
	t.Parallel()
	srv := publicMkCookiesServer(t)
	var calls atomicCounter
	clock := func() time.Time {
		calls.Add(1)
		return time.Unix(1_700_000_000, 0).UTC()
	}
	h := acidns.HandlerFunc(func(_ context.Context, w acidns.ResponseWriter, q wire.Message) {
		resp, _ := wire.NewMessageBuilder().ID(q.ID()).Response(true).
			Question(q.Questions()[0]).Build()
		_ = w.WriteMsg(resp)
	})
	mw, err := acidns.NewCookies(h, srv, acidns.WithCookieClock(clock))
	require.NoError(t, err)

	// Build a query that carries a client cookie — that's the input
	// shape that drives the cookies middleware to consult its clock.
	clientOpt := wire.NewClientCookie([8]byte{1, 2, 3, 4, 5, 6, 7, 8})
	ed, err := wire.NewEDNSBuilder().Option(clientOpt).Build()
	require.NoError(t, err)
	q, err := wire.NewMessageBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		EDNS(ed).
		Build()
	require.NoError(t, err)
	mw.ServeDNS(t.Context(), &coverageWriter{src: netip.MustParseAddrPort("198.51.100.5:1")}, q)

	require.Positive(t, calls.Load(),
		"WithCookieClock-injected clock must be consulted on a cookie-bearing query")
}

// TestRRLIPv6PrefixAccepted covers WithRRLIPv6Prefix. The prefix only
// has an observable effect for IPv6 source aggregation; verifying the
// aggregation runtime requires firing v6 traffic through the middleware
// (out of scope here). Construction acceptance is documented separately
// from behaviour so the intent is honest.
func TestRRLIPv6PrefixAccepted(t *testing.T) {
	t.Parallel()
	h := acidns.HandlerFunc(func(_ context.Context, _ acidns.ResponseWriter, _ wire.Message) {})
	rrlH := acidns.NewRRL(h, acidns.WithRRLIPv6Prefix(48))
	require.NotNil(t, rrlH)
}

// coverageWriter is a minimal ResponseWriter for tests in this file
// that drive a handler purely to observe middleware side effects
// (clock consultation, counter increments) and don't need to inspect
// the response wire bytes. Distinct from middleware_observe_test.go's
// recordingWriter, which captures the response message.
type coverageWriter struct {
	src netip.AddrPort
}

func (coverageWriter) WriteMsg(wire.Message) error    { return nil }
func (coverageWriter) Network() string                { return "udp" }
func (coverageWriter) LocalAddr() netip.AddrPort      { return netip.AddrPort{} }
func (c coverageWriter) RemoteAddr() netip.AddrPort   { return c.src }

// atomicCounter is a tiny sync wrapper around an int — sufficient for
// the test's "did the injected clock callback fire?" question.
type atomicCounter struct {
	mu sync.Mutex
	v  int
}

func (a *atomicCounter) Add(delta int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.v += delta
}

func (a *atomicCounter) Load() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.v
}
