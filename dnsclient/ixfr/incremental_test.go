package ixfr_test

import (
	"context"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient/ixfr"
	"github.com/lestrrat-go/acidns/dnsclient/transport"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// fakeStream serves a fixed list of pre-built messages.
type fakeStream struct {
	msgs []wire.Message
	idx  int
}

func (f *fakeStream) Next(_ context.Context) (wire.Message, error) {
	if f.idx >= len(f.msgs) {
		return nil, io.EOF
	}
	m := f.msgs[f.idx]
	f.idx++
	return m, nil
}
func (f *fakeStream) Close() error { return nil }

type fakeStreamExchanger struct{ stream *fakeStream }

func (f *fakeStreamExchanger) Exchange(_ context.Context, _ wire.Message) (wire.Message, error) {
	return nil, io.EOF
}
func (f *fakeStreamExchanger) Stream(_ context.Context, _ wire.Message) (transport.MessageStream, error) {
	return f.stream, nil
}

func mkSOA(serial uint32) rdata.SOA {
	return rdata.NewSOA(
		wire.MustParseName("ns.example.com"),
		wire.MustParseName("hm.example.com"),
		serial,
		7200*time.Second, 3600*time.Second, 1209600*time.Second, 60*time.Second,
	)
}

func soaRR(serial uint32) wire.Record {
	return wire.NewRecord(wire.MustParseName("example.com"), 60*time.Second, mkSOA(serial))
}

// TestIncrementalDiffEvents drives the incremental code path with a single
// sub-diff: serial 100 → 101, removing one A record, adding one.
func TestIncrementalDiffEvents(t *testing.T) {
	t.Parallel()

	zone := wire.MustParseName("example.com")
	removed := wire.NewRecord(wire.MustParseName("a.example.com"), 60*time.Second,
		rdata.NewA(netip.MustParseAddr("192.0.2.1")))
	added := wire.NewRecord(wire.MustParseName("b.example.com"), 60*time.Second,
		rdata.NewA(netip.MustParseAddr("192.0.2.2")))

	// Wire layout:
	//   SOA(101)               // newSOA — declared up front
	//   SOA(100)               // old serial — start of sub-diff
	//   removed
	//   SOA(101)               // new serial mid-diff — end of removed list
	//   added
	//   SOA(101)               // closing bracket
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
	xfer, err := ixfr.Start(t.Context(), ex, zone, mkSOA(100), ixfr.WithTimeout(time.Second))
	require.NoError(t, err)
	defer xfer.Close()
	require.Equal(t, ixfr.KindIncremental, xfer.Kind())
	require.Equal(t, uint32(101), xfer.NewSOA().Serial())

	ev, err := xfer.Next(t.Context())
	require.NoError(t, err)
	de, ok := ev.(ixfr.DiffEvent)
	require.True(t, ok)
	require.Equal(t, uint32(100), de.FromSerial())
	require.Equal(t, uint32(101), de.ToSerial())
	require.Len(t, de.Removed(), 1)
	require.Len(t, de.Added(), 1)
	require.Equal(t, rrtype.A, de.Added()[0].Type())

	_, err = xfer.Next(t.Context())
	require.ErrorIs(t, err, io.EOF)
}

// TestUpToDate covers the path where the server reports the client is
// already current: a single SOA record with the client's own serial.
func TestUpToDate(t *testing.T) {
	t.Parallel()
	resp, err := wire.NewBuilder().
		ID(1).Response(true).
		Answer(soaRR(50)).
		Build()
	require.NoError(t, err)
	ex := &fakeStreamExchanger{stream: &fakeStream{msgs: []wire.Message{resp}}}
	xfer, err := ixfr.Start(t.Context(), ex, wire.MustParseName("example.com"), mkSOA(50))
	require.NoError(t, err)
	defer xfer.Close()
	require.Equal(t, ixfr.KindUpToDate, xfer.Kind())
}
