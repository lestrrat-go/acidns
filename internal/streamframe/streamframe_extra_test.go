package streamframe_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/internal/streamframe"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// failWriter returns errFailWriter on Write calls after `okCalls` successful
// writes (which are silently dropped).
type failWriter struct {
	mu       sync.Mutex
	okCalls  int
	written  [][]byte
	errAfter error
}

var errFailWriter = errors.New("failWriter: forced error")

func (w *failWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.okCalls > 0 {
		w.okCalls--
		buf := make([]byte, len(p))
		copy(buf, p)
		w.written = append(w.written, buf)
		return len(p), nil
	}
	return 0, w.errAfter
}

// failReader returns the supplied bytes for `ok` reads, then errFailReader.
type failReader struct {
	data []byte
	off  int
	err  error
}

var errFailReader = errors.New("failReader: forced error")

func (r *failReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		if r.err != nil {
			return 0, r.err
		}
		return 0, io.EOF
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	return n, nil
}

func mustQ(t *testing.T, id uint16) wire.Message {
	t.Helper()
	q, err := wire.NewBuilder().
		ID(id).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	require.NoError(t, err)
	return q
}

func mustResp(t *testing.T, id uint16) wire.Message {
	t.Helper()
	r, err := wire.NewBuilder().
		ID(id).
		Response(true).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	require.NoError(t, err)
	return r
}

// buildOversized builds a message > 0xffff bytes by stuffing many TXT
// records into the additional section.
func buildOversized(t *testing.T) wire.Message {
	t.Helper()
	txt, err := rdata.NewTXT(string(bytes.Repeat([]byte{'x'}, 255)))
	require.NoError(t, err)
	rec := wire.NewRecord(wire.MustParseName("example.com"), time.Minute, txt)

	b := wire.NewBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A))
	// each record contributes ~270 bytes; 300 → ~80KB > 64KB.
	for i := 0; i < 300; i++ {
		b = b.Additional(rec)
	}
	m, err := b.Build()
	require.NoError(t, err)
	return m
}

func TestWriteFrameOversized(t *testing.T) {
	t.Parallel()
	m := buildOversized(t)
	var buf bytes.Buffer
	err := streamframe.WriteFrame(&buf, m)
	require.Error(t, err)
	require.Contains(t, err.Error(), "too large")
}

func TestWriteFrameLengthWriteError(t *testing.T) {
	t.Parallel()
	w := &failWriter{okCalls: 0, errAfter: errFailWriter}
	err := streamframe.WriteFrame(w, mustQ(t, 1))
	require.Error(t, err)
	require.ErrorIs(t, err, errFailWriter)
	require.Contains(t, err.Error(), "write length")
}

func TestWriteFrameBodyWriteError(t *testing.T) {
	t.Parallel()
	// First write (length header) succeeds, second (body) fails.
	w := &failWriter{okCalls: 1, errAfter: errFailWriter}
	err := streamframe.WriteFrame(w, mustQ(t, 1))
	require.Error(t, err)
	require.ErrorIs(t, err, errFailWriter)
	require.Contains(t, err.Error(), "write body")
}

func TestReadFrameUnmarshalError(t *testing.T) {
	t.Parallel()
	// Length 5, then 5 garbage bytes (header too short for DNS).
	r := bytes.NewReader([]byte{0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05})
	_, err := streamframe.ReadFrame(r)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unmarshal")
}

func TestReadFrameBodyReadError(t *testing.T) {
	t.Parallel()
	// Length header reads fine; mid-body read returns a non-EOF error.
	r := &failReader{data: []byte{0x00, 0x10}, err: errFailReader}
	_, err := streamframe.ReadFrame(r)
	require.Error(t, err)
	require.ErrorIs(t, err, errFailReader)
	require.Contains(t, err.Error(), "read body")
}

func TestReadFramePartialHeaderReturnsUnexpectedEOF(t *testing.T) {
	t.Parallel()
	// Only 1 byte of the 2-byte length header.
	_, err := streamframe.ReadFrame(bytes.NewReader([]byte{0x00}))
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestReadFrameZeroLengthBodyTriggersUnmarshalError(t *testing.T) {
	t.Parallel()
	// Length 0 → empty body → wire.Unmarshal rejects header-too-short.
	_, err := streamframe.ReadFrame(bytes.NewReader([]byte{0x00, 0x00}))
	require.ErrorIs(t, err, wire.ErrInvalidMessage)
}

func TestReadFramePartialReadsAreLooped(t *testing.T) {
	t.Parallel()
	// Encode a real frame, then deliver it one byte at a time. io.ReadFull
	// must loop until all bytes arrive.
	var buf bytes.Buffer
	require.NoError(t, streamframe.WriteFrame(&buf, mustResp(t, 0xbeef)))

	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		for _, b := range buf.Bytes() {
			_, _ = pw.Write([]byte{b})
		}
	}()
	got, err := streamframe.ReadFrame(pr)
	require.NoError(t, err)
	require.Equal(t, uint16(0xbeef), got.ID())
}

func TestExchangeWithCtxDeadline(t *testing.T) {
	t.Parallel()
	c1, c2 := net.Pipe()
	defer c2.Close()

	go func() {
		req, err := streamframe.ReadFrame(c2)
		if err != nil {
			return
		}
		_ = streamframe.WriteFrame(c2, mustResp(t, req.ID()))
	}()

	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(time.Second))
	defer cancel()
	resp, err := streamframe.Exchange(ctx, c1, mustQ(t, 0x1111), 0)
	require.NoError(t, err)
	require.Equal(t, uint16(0x1111), resp.ID())
}

func TestExchangeWriteError(t *testing.T) {
	t.Parallel()
	c1, c2 := net.Pipe()
	// Close peer immediately so the first Write fails.
	require.NoError(t, c2.Close())

	_, err := streamframe.Exchange(t.Context(), c1, mustQ(t, 1), 100*time.Millisecond)
	require.ErrorIs(t, err, io.ErrClosedPipe)
}

func TestExchangeReadErrorReturnsCtxErrWhenCancelled(t *testing.T) {
	t.Parallel()
	c1, c2 := net.Pipe()
	defer c2.Close()

	ctx, cancel := context.WithCancel(t.Context())
	// Server reads the request — guaranteeing WriteFrame returned and
	// Exchange has reached ReadFrame — and only then cancels. This is
	// race-free: no sleep is needed to order cancel after the write.
	go func() {
		_, _ = streamframe.ReadFrame(c2)
		cancel()
	}()
	_, err := streamframe.Exchange(ctx, c1, mustQ(t, 2), time.Hour)
	require.Error(t, err)
	require.ErrorIs(t, err, context.Canceled)
}

func TestExchangeReadErrorWithoutCtxCancel(t *testing.T) {
	t.Parallel()
	c1, c2 := net.Pipe()

	// Server reads request, then closes without replying.
	go func() {
		_, _ = streamframe.ReadFrame(c2)
		_ = c2.Close()
	}()

	_, err := streamframe.Exchange(t.Context(), c1, mustQ(t, 3), time.Hour)
	require.ErrorIs(t, err, io.EOF)
	// Must NOT be a context error since ctx wasn't cancelled.
	require.NotErrorIs(t, err, context.Canceled)
	require.NotErrorIs(t, err, context.DeadlineExceeded)
}

func TestNewConnStreamWithCtxDeadline(t *testing.T) {
	t.Parallel()
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	go func() { _, _ = streamframe.ReadFrame(c2) }()

	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(time.Second))
	defer cancel()
	stream, err := streamframe.NewConnStream(ctx, c1, mustQ(t, 0x4242), 0)
	require.NoError(t, err)
	require.NoError(t, stream.Close())
}

func TestNewConnStreamWriteError(t *testing.T) {
	t.Parallel()
	c1, c2 := net.Pipe()
	require.NoError(t, c2.Close())

	_, err := streamframe.NewConnStream(t.Context(), c1, mustQ(t, 1), 100*time.Millisecond)
	require.ErrorIs(t, err, io.ErrClosedPipe)
}

func TestNewConnStreamCtxCancelClosesConn(t *testing.T) {
	t.Parallel()
	c1, c2 := net.Pipe()
	defer c2.Close()

	// Server reads but doesn't reply, just to keep the conn alive.
	go func() { _, _ = streamframe.ReadFrame(c2) }()

	ctx, cancel := context.WithCancel(t.Context())
	stream, err := streamframe.NewConnStream(ctx, c1, mustQ(t, 0x55), time.Hour)
	require.NoError(t, err)

	// Cancel ctx, then Next should observe a cancelled context error.
	cancel()
	_, err = stream.Next(t.Context())
	// Cancel races the conn close — surfaces as either context.Canceled or
	// io.ErrClosedPipe depending on which path the read goroutine takes.
	require.Error(t, err)
	require.NoError(t, stream.Close())
}

func TestConnStreamNextWithCtxDeadline(t *testing.T) {
	t.Parallel()
	c1, c2 := net.Pipe()
	defer c2.Close()

	go func() {
		_, _ = streamframe.ReadFrame(c2)
		_ = streamframe.WriteFrame(c2, mustResp(t, 0x77))
	}()

	stream, err := streamframe.NewConnStream(t.Context(), c1, mustQ(t, 0x77), time.Hour)
	require.NoError(t, err)
	defer stream.Close()

	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(time.Second))
	defer cancel()
	resp, err := stream.Next(ctx)
	require.NoError(t, err)
	require.Equal(t, uint16(0x77), resp.ID())
}

func TestConnStreamNextCtxCancelDuringRead(t *testing.T) {
	t.Parallel()
	c1, c2 := net.Pipe()
	defer c2.Close()

	// Server reads request — proving NewConnStream finished WriteFrame —
	// and only then we proceed to call Next.
	written := make(chan struct{})
	go func() {
		_, _ = streamframe.ReadFrame(c2)
		close(written)
	}()

	stream, err := streamframe.NewConnStream(t.Context(), c1, mustQ(t, 0x88), time.Hour)
	require.NoError(t, err)
	defer stream.Close()

	<-written
	ctx, cancel := context.WithCancel(t.Context())
	cancel() // ctx is already done before Next observes it
	_, err = stream.Next(ctx)
	require.Error(t, err)
	require.ErrorIs(t, err, context.Canceled)
}

func TestConnStreamIDMismatch(t *testing.T) {
	t.Parallel()
	c1, c2 := net.Pipe()
	defer c2.Close()

	go func() {
		_, _ = streamframe.ReadFrame(c2)
		_ = streamframe.WriteFrame(c2, mustResp(t, 0x9999))
	}()

	stream, err := streamframe.NewConnStream(t.Context(), c1, mustQ(t, 0x1010), time.Hour)
	require.NoError(t, err)
	defer stream.Close()

	_, err = stream.Next(t.Context())
	require.Error(t, err)
	require.Contains(t, err.Error(), "id mismatch")
}
