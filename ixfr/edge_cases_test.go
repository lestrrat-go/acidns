package ixfr_test

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/ixfr"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// errStreamExchanger fails Stream() with a custom error to drive Start's
// "open stream" failure path.
type errStreamExchanger struct{ err error }

func (e *errStreamExchanger) Exchange(_ context.Context, _ wire.Message) (wire.Message, error) {
	return nil, e.err
}
func (e *errStreamExchanger) Stream(_ context.Context, _ wire.Message) (acidns.MessageStream, error) {
	return nil, e.err
}

// errStream returns a custom error from Next(), once.
type errStream struct {
	err  error
	done bool
}

func (e *errStream) Next(_ context.Context) (wire.Message, error) {
	if e.done {
		return nil, io.EOF
	}
	e.done = true
	return nil, e.err
}
func (e *errStream) Close() error { return nil }

type errStreamExchangerOpens struct{ s acidns.MessageStream }

func (e *errStreamExchangerOpens) Exchange(_ context.Context, _ wire.Message) (wire.Message, error) {
	return nil, io.EOF
}
func (e *errStreamExchangerOpens) Stream(_ context.Context, _ wire.Message) (acidns.MessageStream, error) {
	return e.s, nil
}

func aRR(name string, ip string) wire.Record {
	return wire.NewRecord(wire.MustParseName(name), 60*time.Second,
		rdata.NewA(netip.MustParseAddr(ip)))
}

// TestStartStreamError covers the "ex.Stream returned error" branch in Start.
func TestStartStreamError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("dial failed")
	ex := &errStreamExchanger{err: sentinel}
	_, err := ixfr.Start(t.Context(), ex, wire.MustParseName("example.com"), mkSOA(1))
	require.Error(t, err)
	require.ErrorIs(t, err, sentinel)
}

// TestStartEmptyResponse covers init's "empty response" branch (stream
// returns io.EOF immediately).
func TestStartEmptyResponse(t *testing.T) {
	t.Parallel()
	ex := &errStreamExchangerOpens{s: &fakeStream{msgs: nil}}
	_, err := ixfr.Start(t.Context(), ex, wire.MustParseName("example.com"), mkSOA(1))
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty response")
}

// TestStartFirstReadError covers init's "err != nil" branch on the first
// record read (stream.Next returns a non-EOF error).
func TestStartFirstReadError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("network down")
	ex := &errStreamExchangerOpens{s: &errStream{err: sentinel}}
	_, err := ixfr.Start(t.Context(), ex, wire.MustParseName("example.com"), mkSOA(1))
	require.Error(t, err)
	require.ErrorIs(t, err, sentinel)
}

// TestStartFirstNotSOA covers the "stream must begin with SOA" branch.
func TestStartFirstNotSOA(t *testing.T) {
	t.Parallel()
	resp, err := wire.NewBuilder().
		ID(1).Response(true).
		Answer(aRR("foo.example.com", "192.0.2.1")).
		Build()
	require.NoError(t, err)
	ex := &fakeStreamExchanger{stream: &fakeStream{msgs: []wire.Message{resp}}}
	_, err = ixfr.Start(t.Context(), ex, wire.MustParseName("example.com"), mkSOA(1))
	require.Error(t, err)
	require.Contains(t, err.Error(), "must begin with SOA")
}

// TestStartSecondReadError covers init's "err != nil" branch on the second
// record read.
type firstThenErrStream struct {
	first wire.Message
	err   error
	idx   int
}

func (s *firstThenErrStream) Next(_ context.Context) (wire.Message, error) {
	s.idx++
	if s.idx == 1 {
		return s.first, nil
	}
	return nil, s.err
}
func (s *firstThenErrStream) Close() error { return nil }

func TestStartSecondReadError(t *testing.T) {
	t.Parallel()
	// First message has only a single SOA record, then stream errors.
	resp, err := wire.NewBuilder().ID(1).Response(true).Answer(soaRR(100)).Build()
	require.NoError(t, err)
	sentinel := errors.New("stream torn down")
	ex := &errStreamExchangerOpens{s: &firstThenErrStream{first: resp, err: sentinel}}
	_, err = ixfr.Start(t.Context(), ex, wire.MustParseName("example.com"), mkSOA(50))
	require.Error(t, err)
	require.ErrorIs(t, err, sentinel)
}

// TestStartEmptyAXFRFallback covers the "Empty AXFR-fallback" branch where
// the bracketing SOAs match each other but not the client's serial.
func TestStartEmptyAXFRFallback(t *testing.T) {
	t.Parallel()
	resp, err := wire.NewBuilder().
		ID(1).Response(true).
		Answer(soaRR(100)).
		Answer(soaRR(100)).
		Build()
	require.NoError(t, err)
	ex := &fakeStreamExchanger{stream: &fakeStream{msgs: []wire.Message{resp}}}
	xfer, err := ixfr.Start(t.Context(), ex, wire.MustParseName("example.com"), mkSOA(50))
	require.NoError(t, err)
	defer func() { _ = xfer.Close() }()
	require.Equal(t, ixfr.KindAXFRFallback, xfer.Kind())

	// First event is the leading SOA(100); second is closing SOA(100).
	ev, err := xfer.Next(t.Context())
	require.NoError(t, err)
	rec, ok := ev.(ixfr.RecordEvent)
	require.True(t, ok)
	require.Equal(t, rrtype.SOA, rec.Record().Type())

	ev, err = xfer.Next(t.Context())
	require.NoError(t, err)
	rec, ok = ev.(ixfr.RecordEvent)
	require.True(t, ok)
	require.Equal(t, rrtype.SOA, rec.Record().Type())

	_, err = xfer.Next(t.Context())
	require.ErrorIs(t, err, io.EOF)
}

// TestStartUpToDateTwoSOAs covers the "rec2.Serial() == newSOA.Serial() &&
// newSOA.Serial() == clientSerial" branch — equivalent to UpToDate even
// when the server emits a second matching SOA.
func TestStartUpToDateTwoSOAs(t *testing.T) {
	t.Parallel()
	resp, err := wire.NewBuilder().
		ID(1).Response(true).
		Answer(soaRR(50)).
		Answer(soaRR(50)).
		Build()
	require.NoError(t, err)
	ex := &fakeStreamExchanger{stream: &fakeStream{msgs: []wire.Message{resp}}}
	xfer, err := ixfr.Start(t.Context(), ex, wire.MustParseName("example.com"), mkSOA(50))
	require.NoError(t, err)
	defer func() { _ = xfer.Close() }()
	require.Equal(t, ixfr.KindUpToDate, xfer.Kind())

	// Next on UpToDate immediately returns io.EOF.
	_, err = xfer.Next(t.Context())
	require.ErrorIs(t, err, io.EOF)
}

// TestStartInvalidSOAPair covers the "rec2 serial newer than rec1" branch.
// rec1 (newSOA) reports serial 100; rec2 reports serial 200, which is
// newer per RFC 1982 — invalid.
func TestStartInvalidSOAPair(t *testing.T) {
	t.Parallel()
	resp, err := wire.NewBuilder().
		ID(1).Response(true).
		Answer(soaRR(100)).
		Answer(soaRR(200)).
		Build()
	require.NoError(t, err)
	ex := &fakeStreamExchanger{stream: &fakeStream{msgs: []wire.Message{resp}}}
	_, err = ixfr.Start(t.Context(), ex, wire.MustParseName("example.com"), mkSOA(50))
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid SOA pair")
}

// TestNextAXFRReadError covers nextAXFR's "err != nil" branch by feeding
// a single SOA in the first message, then a stream error.
func TestNextAXFRReadError(t *testing.T) {
	t.Parallel()
	// Build a response with leading SOA + non-SOA record so init sets
	// KindAXFRFallback and pushes both records back. Then we exhaust
	// the pushback and the next stream read must fail.
	resp, err := wire.NewBuilder().
		ID(1).Response(true).
		Answer(soaRR(100)).
		Answer(aRR("foo.example.com", "192.0.2.1")).
		Build()
	require.NoError(t, err)
	sentinel := errors.New("connection reset")
	ex := &errStreamExchangerOpens{s: &firstThenErrStream{first: resp, err: sentinel}}
	xfer, err := ixfr.Start(t.Context(), ex, wire.MustParseName("example.com"), mkSOA(50))
	require.NoError(t, err)
	defer func() { _ = xfer.Close() }()
	require.Equal(t, ixfr.KindAXFRFallback, xfer.Kind())

	// Drain the two pushed-back records.
	_, err = xfer.Next(t.Context())
	require.NoError(t, err)
	_, err = xfer.Next(t.Context())
	require.NoError(t, err)
	// Next read pulls from stream → sentinel.
	_, err = xfer.Next(t.Context())
	require.ErrorIs(t, err, sentinel)
}

// TestNextIncrementalUnexpectedAfterClosing covers the "unexpected record
// after closing SOA" path inside nextIncremental: the closing SOA is
// followed by another record before EOF.
func TestNextIncrementalUnexpectedAfterClosing(t *testing.T) {
	t.Parallel()
	zone := wire.MustParseName("example.com")
	removed := aRR("a.example.com", "192.0.2.1")
	added := aRR("b.example.com", "192.0.2.2")
	resp, err := wire.NewBuilder().
		ID(1).Response(true).
		Answer(soaRR(101)).        // newSOA
		Answer(soaRR(100)).        // sub-diff start
		Answer(removed).
		Answer(soaRR(101)).        // mid-diff
		Answer(added).
		Answer(soaRR(101)).        // closing
		Answer(aRR("trailing.example.com", "192.0.2.99")). // trailing!
		Build()
	require.NoError(t, err)
	ex := &fakeStreamExchanger{stream: &fakeStream{msgs: []wire.Message{resp}}}
	xfer, err := ixfr.Start(t.Context(), ex, zone, mkSOA(100))
	require.NoError(t, err)
	defer func() { _ = xfer.Close() }()
	require.Equal(t, ixfr.KindIncremental, xfer.Kind())

	// First Next yields the diff event; the trailing SOA gets pushed back.
	_, err = xfer.Next(t.Context())
	require.NoError(t, err)

	// Second Next sees the SOA(101) closing bracket then hits the trailing
	// non-SOA — should error.
	_, err = xfer.Next(t.Context())
	require.Error(t, err)
	require.Contains(t, err.Error(), "unexpected record after closing SOA")
}

// TestNextIncrementalAfterDoneEOF: drain a normal incremental, then call
// Next again to confirm io.EOF is repeated (covers `incDone` early-return).
func TestNextIncrementalAfterDoneEOF(t *testing.T) {
	t.Parallel()
	zone := wire.MustParseName("example.com")
	removed := aRR("a.example.com", "192.0.2.1")
	added := aRR("b.example.com", "192.0.2.2")
	resp, err := wire.NewBuilder().
		ID(1).Response(true).
		Answer(soaRR(101)).
		Answer(soaRR(100)).
		Answer(removed).
		Answer(soaRR(101)).
		Answer(added).
		Answer(soaRR(101)).
		Build()
	require.NoError(t, err)
	ex := &fakeStreamExchanger{stream: &fakeStream{msgs: []wire.Message{resp}}}
	xfer, err := ixfr.Start(t.Context(), ex, zone, mkSOA(100))
	require.NoError(t, err)
	defer func() { _ = xfer.Close() }()

	_, err = xfer.Next(t.Context())
	require.NoError(t, err)
	_, err = xfer.Next(t.Context())
	require.ErrorIs(t, err, io.EOF)
	// Second EOF — incDone early return.
	_, err = xfer.Next(t.Context())
	require.ErrorIs(t, err, io.EOF)
}

// TestNextIncrementalSubDiffStartReadError covers the "read sub-diff
// start" error path: after init consumes the first SOA and pushes back
// the second, exhausting both via Next must error from a stream-level
// failure on the next read.
//
// We arrange this by having init see SOA(101) then SOA(100) (incremental
// kind), then on the next Next() the reader pulls the pushed-back SOA(100)
// (sub-diff start), then another record (removed) — but stream errors mid-
// removed-list so we hit "ixfr: read removed:" wrap. That covers the read
// removed error branch.
func TestNextIncrementalReadRemovedError(t *testing.T) {
	t.Parallel()
	zone := wire.MustParseName("example.com")
	first, err := wire.NewBuilder().
		ID(1).Response(true).
		Answer(soaRR(101)).        // newSOA
		Answer(soaRR(100)).        // sub-diff start (gets pushed back)
		Build()
	require.NoError(t, err)
	sentinel := errors.New("torn mid-removed")
	ex := &errStreamExchangerOpens{s: &firstThenErrStream{first: first, err: sentinel}}
	xfer, err := ixfr.Start(t.Context(), ex, zone, mkSOA(100))
	require.NoError(t, err)
	defer func() { _ = xfer.Close() }()
	require.Equal(t, ixfr.KindIncremental, xfer.Kind())

	_, err = xfer.Next(t.Context())
	require.Error(t, err)
	// Wrapped by either "read removed" or "read sub-diff start" depending on
	// whether the pushed-back SOA was already consumed. Either is a valid
	// error path; just check the sentinel propagates.
	require.ErrorIs(t, err, sentinel)
}

// TestNextIncrementalReadAddedError covers the "read added" error path:
// a single message contains SOA_new, SOA_old, removed, SOA_new, then the
// stream errors before the added section completes (without closing SOA).
func TestNextIncrementalReadAddedError(t *testing.T) {
	t.Parallel()
	zone := wire.MustParseName("example.com")
	first, err := wire.NewBuilder().
		ID(1).Response(true).
		Answer(soaRR(101)).
		Answer(soaRR(100)).
		Answer(aRR("a.example.com", "192.0.2.1")).
		Answer(soaRR(101)). // mid-diff; switches to added
		// next record would be added… stream errors instead.
		Build()
	require.NoError(t, err)
	sentinel := errors.New("torn mid-added")
	ex := &errStreamExchangerOpens{s: &firstThenErrStream{first: first, err: sentinel}}
	xfer, err := ixfr.Start(t.Context(), ex, zone, mkSOA(100))
	require.NoError(t, err)
	defer func() { _ = xfer.Close() }()

	_, err = xfer.Next(t.Context())
	require.Error(t, err)
	require.ErrorIs(t, err, sentinel)
}

// TestNextIncrementalNoClosingSOA covers "stream ended without closing
// SOA" — the added section runs all the way to io.EOF.
func TestNextIncrementalNoClosingSOA(t *testing.T) {
	t.Parallel()
	zone := wire.MustParseName("example.com")
	resp, err := wire.NewBuilder().
		ID(1).Response(true).
		Answer(soaRR(101)).
		Answer(soaRR(100)).
		Answer(aRR("a.example.com", "192.0.2.1")).
		Answer(soaRR(101)).
		Answer(aRR("b.example.com", "192.0.2.2")).
		// No closing SOA(101).
		Build()
	require.NoError(t, err)
	ex := &fakeStreamExchanger{stream: &fakeStream{msgs: []wire.Message{resp}}}
	xfer, err := ixfr.Start(t.Context(), ex, zone, mkSOA(100))
	require.NoError(t, err)
	defer func() { _ = xfer.Close() }()

	_, err = xfer.Next(t.Context())
	require.Error(t, err)
	require.Contains(t, err.Error(), "stream ended without closing SOA")
}

// TestNextIncrementalMultiMessage covers spanning a single incremental
// transfer across two stream messages — verifies recReader rolls over.
func TestNextIncrementalMultiMessage(t *testing.T) {
	t.Parallel()
	zone := wire.MustParseName("example.com")
	msg1, err := wire.NewBuilder().
		ID(1).Response(true).
		Answer(soaRR(101)).
		Answer(soaRR(100)).
		Answer(aRR("a.example.com", "192.0.2.1")).
		Build()
	require.NoError(t, err)
	msg2, err := wire.NewBuilder().
		ID(1).Response(true).
		Answer(soaRR(101)).
		Answer(aRR("b.example.com", "192.0.2.2")).
		Answer(soaRR(101)).
		Build()
	require.NoError(t, err)
	ex := &fakeStreamExchanger{stream: &fakeStream{msgs: []wire.Message{msg1, msg2}}}
	xfer, err := ixfr.Start(t.Context(), ex, zone, mkSOA(100))
	require.NoError(t, err)
	defer func() { _ = xfer.Close() }()

	ev, err := xfer.Next(t.Context())
	require.NoError(t, err)
	de, ok := ev.(ixfr.DiffEvent)
	require.True(t, ok)
	require.Len(t, de.Removed(), 1)
	require.Len(t, de.Added(), 1)

	_, err = xfer.Next(t.Context())
	require.ErrorIs(t, err, io.EOF)
}

// TestRecReaderRcodeError covers the "RCODE != NoError" error in
// recReader.Read by having the second message carry SERVFAIL.
func TestRecReaderRcodeError(t *testing.T) {
	t.Parallel()
	zone := wire.MustParseName("example.com")
	msg1, err := wire.NewBuilder().
		ID(1).Response(true).
		Answer(soaRR(101)).
		Answer(soaRR(100)).
		Build()
	require.NoError(t, err)
	msg2, err := wire.NewBuilder().
		ID(1).Response(true).RCODE(wire.RCODEServFail).
		Build()
	require.NoError(t, err)
	ex := &fakeStreamExchanger{stream: &fakeStream{msgs: []wire.Message{msg1, msg2}}}
	xfer, err := ixfr.Start(t.Context(), ex, zone, mkSOA(100))
	require.NoError(t, err)
	defer func() { _ = xfer.Close() }()

	_, err = xfer.Next(t.Context())
	require.Error(t, err)
	require.Contains(t, err.Error(), "SERVFAIL")
}

// TestRcodeErrorAtInit covers the rcode-check inside init's first read.
func TestRcodeErrorAtInit(t *testing.T) {
	t.Parallel()
	resp, err := wire.NewBuilder().
		ID(1).Response(true).RCODE(wire.RCODERefused).
		Build()
	require.NoError(t, err)
	ex := &fakeStreamExchanger{stream: &fakeStream{msgs: []wire.Message{resp}}}
	_, err = ixfr.Start(t.Context(), ex, wire.MustParseName("example.com"), mkSOA(100))
	require.Error(t, err)
	require.Contains(t, err.Error(), "REFUSED")
}

// TestSerialIsOlderViaIncremental indirectly drives serialIsOlder around
// the RFC 1982 wrap — client serial ~= 0xFFFFFFFF, server bumps to small
// value. The wire-level check in init() must still classify rec2 (client's
// old serial) as older than rec1 (server's new low serial).
func TestSerialWrapAroundIncremental(t *testing.T) {
	t.Parallel()
	zone := wire.MustParseName("example.com")
	const oldSerial uint32 = 0xFFFFFFF0
	const newSerial uint32 = 5 // wraps; per RFC 1982 newSerial > oldSerial
	resp, err := wire.NewBuilder().
		ID(1).Response(true).
		Answer(soaRR(newSerial)).
		Answer(soaRR(oldSerial)).
		Answer(aRR("gone.example.com", "192.0.2.50")).
		Answer(soaRR(newSerial)).
		Answer(aRR("new.example.com", "192.0.2.60")).
		Answer(soaRR(newSerial)).
		Build()
	require.NoError(t, err)
	ex := &fakeStreamExchanger{stream: &fakeStream{msgs: []wire.Message{resp}}}
	xfer, err := ixfr.Start(t.Context(), ex, zone, mkSOA(oldSerial))
	require.NoError(t, err)
	defer func() { _ = xfer.Close() }()
	require.Equal(t, ixfr.KindIncremental, xfer.Kind())
	require.Equal(t, newSerial, xfer.NewSOA().Serial())

	ev, err := xfer.Next(t.Context())
	require.NoError(t, err)
	de, ok := ev.(ixfr.DiffEvent)
	require.True(t, ok)
	require.Equal(t, oldSerial, de.FromSerial())
	require.Equal(t, newSerial, de.ToSerial())

	_, err = xfer.Next(t.Context())
	require.ErrorIs(t, err, io.EOF)
}

// TestWithTimeoutOption exercises the Option apply path (currently the
// timeout value is reserved-for-future-use, but the option must still
// flow through Start without error).
func TestWithTimeoutOption(t *testing.T) {
	t.Parallel()
	resp, err := wire.NewBuilder().
		ID(1).Response(true).
		Answer(soaRR(50)).
		Build()
	require.NoError(t, err)
	ex := &fakeStreamExchanger{stream: &fakeStream{msgs: []wire.Message{resp}}}
	xfer, err := ixfr.Start(t.Context(), ex, wire.MustParseName("example.com"),
		mkSOA(50), ixfr.WithTimeout(2*time.Second))
	require.NoError(t, err)
	defer func() { _ = xfer.Close() }()
	require.Equal(t, ixfr.KindUpToDate, xfer.Kind())
}
