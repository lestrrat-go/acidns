package streamframe_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient/transport/internal/streamframe"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

func mustQuery(t *testing.T, id uint16, name string) wire.Message {
	t.Helper()
	q, err := wire.NewBuilder().
		ID(id).
		Question(wire.NewQuestion(wire.MustParseName(name), rrtype.A)).
		Build()
	require.NoError(t, err)
	return q
}

func mustResponse(t *testing.T, id uint16, name string) wire.Message {
	t.Helper()
	q, err := wire.NewBuilder().
		ID(id).
		Response(true).
		Question(wire.NewQuestion(wire.MustParseName(name), rrtype.A)).
		Build()
	require.NoError(t, err)
	return q
}

func TestWriteReadFrameRoundTrip(t *testing.T) {
	t.Parallel()
	q := mustQuery(t, 0x1234, "example.com")
	var buf bytes.Buffer
	require.NoError(t, streamframe.WriteFrame(&buf, q))

	got, err := streamframe.ReadFrame(&buf)
	require.NoError(t, err)
	require.Equal(t, uint16(0x1234), got.ID())
}

func TestReadFrameEOF(t *testing.T) {
	t.Parallel()
	_, err := streamframe.ReadFrame(bytes.NewReader(nil))
	require.ErrorIs(t, err, io.EOF)
}

func TestReadFrameTruncatedBody(t *testing.T) {
	t.Parallel()
	// length header says 100 bytes but body is empty
	_, err := streamframe.ReadFrame(bytes.NewReader([]byte{0x00, 0x64}))
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestExchange(t *testing.T) {
	t.Parallel()
	c1, c2 := net.Pipe()
	defer c2.Close()

	go func() {
		// Server-side: read request, send response.
		req, err := streamframe.ReadFrame(c2)
		require.NoError(t, err)
		_ = streamframe.WriteFrame(c2, mustResponse(t, req.ID(), "example.com"))
	}()

	q := mustQuery(t, 0xabcd, "example.com")
	resp, err := streamframe.Exchange(context.Background(), c1, q, time.Second)
	require.NoError(t, err)
	require.Equal(t, uint16(0xabcd), resp.ID())
}

func TestExchangeIDMismatch(t *testing.T) {
	t.Parallel()
	c1, c2 := net.Pipe()
	defer c2.Close()
	go func() {
		_, _ = streamframe.ReadFrame(c2)
		_ = streamframe.WriteFrame(c2, mustResponse(t, 0xdead, "example.com"))
	}()
	q := mustQuery(t, 0xbeef, "example.com")
	_, err := streamframe.Exchange(context.Background(), c1, q, time.Second)
	require.ErrorContains(t, err, "id mismatch")
}

func TestConnStream(t *testing.T) {
	t.Parallel()
	c1, c2 := net.Pipe()
	defer c2.Close()

	go func() {
		_, _ = streamframe.ReadFrame(c2)
		// Two responses sharing the same query ID.
		_ = streamframe.WriteFrame(c2, mustResponse(t, 0x4242, "example.com"))
		_ = streamframe.WriteFrame(c2, mustResponse(t, 0x4242, "example.com"))
	}()

	q := mustQuery(t, 0x4242, "example.com")
	stream, err := streamframe.NewConnStream(context.Background(), c1, q, time.Second)
	require.NoError(t, err)
	defer stream.Close()

	r1, err := stream.Next(context.Background())
	require.NoError(t, err)
	require.Equal(t, uint16(0x4242), r1.ID())

	r2, err := stream.Next(context.Background())
	require.NoError(t, err)
	require.Equal(t, uint16(0x4242), r2.ID())

	require.NoError(t, stream.Close())
	// Idempotent close.
	require.NoError(t, stream.Close())
}
