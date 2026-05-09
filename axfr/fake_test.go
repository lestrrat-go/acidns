package axfr_test

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/axfr"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// fakeStream is a scripted MessageStream feeding pre-built messages
// (or errors) to the AXFR client one at a time.
type fakeStream struct {
	msgs   []wire.Message
	errs   []error
	idx    int
	closed bool
}

func (f *fakeStream) Next(_ context.Context) (wire.Message, error) {
	if f.idx >= len(f.msgs) {
		return wire.Message{}, io.EOF
	}
	i := f.idx
	f.idx++
	if f.errs != nil && i < len(f.errs) && f.errs[i] != nil {
		return wire.Message{}, f.errs[i]
	}
	return f.msgs[i], nil
}

func (f *fakeStream) Close() error {
	f.closed = true
	return nil
}

// fakeStreamEx is a scripted StreamExchanger.
type fakeStreamEx struct {
	stream acidns.MessageStream
	err    error
	called bool
}

func (f *fakeStreamEx) Stream(_ context.Context, _ wire.Message) (acidns.MessageStream, error) {
	f.called = true
	if f.err != nil {
		return nil, f.err
	}
	return f.stream, nil
}

func mustBuild(t *testing.T, b *wire.Builder) wire.Message {
	t.Helper()
	m, err := b.Build()
	require.NoError(t, err)
	return m
}

func soaRec(t *testing.T, serial uint32) wire.Record {
	t.Helper()
	return wire.NewRecord(
		wire.MustParseName("example.com"),
		60*time.Second,
		rdata.MustNewSOA(
			wire.MustParseName("ns.example.com"),
			wire.MustParseName("hostmaster.example.com"),
			serial, 7200*time.Second, 3600*time.Second, 1209600*time.Second, 60*time.Second,
		),
	)
}

func aRec(t *testing.T, name string, addr string) wire.Record {
	t.Helper()
	return wire.NewRecord(
		wire.MustParseName(name),
		60*time.Second,
		rdata.MustNewA(netip.MustParseAddr(addr)),
	)
}

func answerMsg(t *testing.T, recs ...wire.Record) wire.Message {
	t.Helper()
	b := wire.NewBuilder().Response(true).RCODE(wire.RCODENoError)
	for _, r := range recs {
		b = b.Answer(r)
	}
	return mustBuild(t, b)
}

func TestStartStreamOpenError(t *testing.T) {
	t.Parallel()
	want := errors.New("dial fail")
	ex := &fakeStreamEx{err: want}
	_, err := axfr.Start(t.Context(), ex, wire.MustParseName("example.com"))
	require.Error(t, err)
	require.ErrorIs(t, err, want)
	require.True(t, ex.called)
}

func TestStartEmptyStream(t *testing.T) {
	t.Parallel()
	stream := &fakeStream{}
	ex := &fakeStreamEx{stream: stream}
	_, err := axfr.Start(t.Context(), ex, wire.MustParseName("example.com"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty response")
	require.True(t, stream.closed, "stream must be closed on init failure")
}

func TestStartLeadingNonSOA(t *testing.T) {
	t.Parallel()
	stream := &fakeStream{
		msgs: []wire.Message{answerMsg(t, aRec(t, "example.com", "192.0.2.1"))},
	}
	ex := &fakeStreamEx{stream: stream}
	_, err := axfr.Start(t.Context(), ex, wire.MustParseName("example.com"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "must begin with SOA")
	require.True(t, stream.closed)
}

func TestStartFirstMessageRCODEError(t *testing.T) {
	t.Parallel()
	bad := mustBuild(t, wire.NewBuilder().Response(true).RCODE(wire.RCODERefused))
	stream := &fakeStream{msgs: []wire.Message{bad}}
	ex := &fakeStreamEx{stream: stream}
	_, err := axfr.Start(t.Context(), ex, wire.MustParseName("example.com"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "axfr:")
	require.True(t, stream.closed)
}

func TestStartFirstMessageStreamError(t *testing.T) {
	t.Parallel()
	want := errors.New("read failed")
	stream := &fakeStream{
		msgs: []wire.Message{wire.Message{}},
		errs: []error{want},
	}
	ex := &fakeStreamEx{stream: stream}
	_, err := axfr.Start(t.Context(), ex, wire.MustParseName("example.com"))
	require.Error(t, err)
	require.ErrorIs(t, err, want)
	require.True(t, stream.closed)
}

// TestNextStreamErrorMidTransfer covers the non-EOF error path inside
// recReader.Read after init has succeeded.
func TestNextStreamErrorMidTransfer(t *testing.T) {
	t.Parallel()
	soa := soaRec(t, 42)
	first := answerMsg(t, soa, aRec(t, "a.example.com", "192.0.2.1"))
	want := errors.New("read failed")
	stream := &fakeStream{
		msgs: []wire.Message{first, wire.Message{}},
		errs: []error{nil, want},
	}
	ex := &fakeStreamEx{stream: stream}
	xfer, err := axfr.Start(t.Context(), ex, wire.MustParseName("example.com"))
	require.NoError(t, err)
	defer func() { _ = xfer.Close() }()

	// Pull leading SOA, then A, then trigger the error fetching the next
	// message.
	ev, err := xfer.Next(t.Context())
	require.NoError(t, err)
	require.Equal(t, rrtype.SOA, ev.Record().Type())

	ev, err = xfer.Next(t.Context())
	require.NoError(t, err)
	require.Equal(t, rrtype.A, ev.Record().Type())

	_, err = xfer.Next(t.Context())
	require.ErrorIs(t, err, want)
}

// TestNextSingleMessageZone exercises the entire transfer (init + body +
// trailing SOA) in a single message and verifies a Next call past EOF
// returns io.EOF without re-reading the stream.
func TestNextSingleMessageZone(t *testing.T) {
	t.Parallel()
	soa := soaRec(t, 7)
	msg := answerMsg(t,
		soa,
		aRec(t, "a.example.com", "192.0.2.1"),
		aRec(t, "b.example.com", "192.0.2.2"),
		soa,
	)
	stream := &fakeStream{msgs: []wire.Message{msg}}
	ex := &fakeStreamEx{stream: stream}

	xfer, err := axfr.Start(t.Context(), ex, wire.MustParseName("example.com"))
	require.NoError(t, err)
	defer func() { _ = xfer.Close() }()

	require.Equal(t, uint32(7), xfer.NewSOA().Serial())

	var seen []wire.Record
	for {
		ev, err := xfer.Next(t.Context())
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		seen = append(seen, ev.Record())
	}
	require.Len(t, seen, 4)
	require.Equal(t, rrtype.SOA, seen[0].Type())
	require.Equal(t, rrtype.SOA, seen[len(seen)-1].Type())

	// Subsequent calls past EOF must keep returning io.EOF.
	_, err = xfer.Next(t.Context())
	require.ErrorIs(t, err, io.EOF)
	_, err = xfer.Next(t.Context())
	require.ErrorIs(t, err, io.EOF)
}

// TestNextMultiMessageZone forces the body to span multiple length-framed
// messages, exercising the recReader's message-rollover path.
func TestNextMultiMessageZone(t *testing.T) {
	t.Parallel()
	soa := soaRec(t, 99)
	first := answerMsg(t, soa, aRec(t, "a.example.com", "192.0.2.1"))
	second := answerMsg(t, aRec(t, "b.example.com", "192.0.2.2"))
	third := answerMsg(t, soa)
	stream := &fakeStream{msgs: []wire.Message{first, second, third}}
	ex := &fakeStreamEx{stream: stream}

	xfer, err := axfr.Start(t.Context(), ex, wire.MustParseName("example.com"))
	require.NoError(t, err)
	defer func() { _ = xfer.Close() }()

	var types []rrtype.Type
	for {
		ev, err := xfer.Next(t.Context())
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		types = append(types, ev.Record().Type())
	}
	require.Equal(t, []rrtype.Type{rrtype.SOA, rrtype.A, rrtype.A, rrtype.SOA}, types)
}

// TestNextStreamEarlyEOF exercises the path where the stream EOFs before a
// closing SOA is observed — the recReader returns io.EOF on the next pull
// and Next surfaces it.
func TestNextStreamEarlyEOF(t *testing.T) {
	t.Parallel()
	soa := soaRec(t, 1)
	msg := answerMsg(t, soa, aRec(t, "a.example.com", "192.0.2.1"))
	stream := &fakeStream{msgs: []wire.Message{msg}}
	ex := &fakeStreamEx{stream: stream}

	xfer, err := axfr.Start(t.Context(), ex, wire.MustParseName("example.com"))
	require.NoError(t, err)
	defer func() { _ = xfer.Close() }()

	// SOA, A, then io.EOF (no closing SOA).
	_, err = xfer.Next(t.Context())
	require.NoError(t, err)
	_, err = xfer.Next(t.Context())
	require.NoError(t, err)
	_, err = xfer.Next(t.Context())
	require.ErrorIs(t, err, io.EOF)

	// And another call still EOF.
	_, err = xfer.Next(t.Context())
	require.ErrorIs(t, err, io.EOF)
}

// TestNextMismatchedClosingSOA verifies that a stream containing a *non-
// matching* SOA mid-transfer is not treated as the closing record (serial
// must match the leading SOA per RFC 5936 §2.2).
func TestNextMismatchedClosingSOA(t *testing.T) {
	t.Parallel()
	leading := soaRec(t, 100)
	mismatched := soaRec(t, 999)
	closing := soaRec(t, 100)
	msg := answerMsg(t,
		leading,
		mismatched,
		aRec(t, "a.example.com", "192.0.2.1"),
		closing,
	)
	stream := &fakeStream{msgs: []wire.Message{msg}}
	ex := &fakeStreamEx{stream: stream}

	xfer, err := axfr.Start(t.Context(), ex, wire.MustParseName("example.com"))
	require.NoError(t, err)
	defer func() { _ = xfer.Close() }()

	var types []rrtype.Type
	for {
		ev, err := xfer.Next(t.Context())
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		types = append(types, ev.Record().Type())
	}
	// Leading SOA, mismatched mid SOA, A, closing SOA.
	require.Equal(t, []rrtype.Type{rrtype.SOA, rrtype.SOA, rrtype.A, rrtype.SOA}, types)
}
