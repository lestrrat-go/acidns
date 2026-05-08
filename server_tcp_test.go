package acidns_test

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

func startTCP(t *testing.T, h acidns.Handler, opts ...acidns.TCPListenerOption) *acidns.Controller {
	t.Helper()
	srv, err := acidns.NewTCPServer(netip.MustParseAddrPort("127.0.0.1:0"), h, opts...)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)
	require.NoError(t, err)
	return ctrl
}

func TestTCPServerEcho(t *testing.T) {
	t.Parallel()

	h := acidns.HandlerFunc(func(_ context.Context, w acidns.ResponseWriter, q wire.Message) {
		ans := wire.NewRecord(q.Questions()[0].Name(), time.Minute,
			rdata.NewA(netip.MustParseAddr("203.0.113.88")))
		resp, _ := wire.NewBuilder().
			ID(q.ID()).
			Response(true).
			Question(q.Questions()[0]).
			Answer(ans).
			Build()
		_ = w.WriteMsg(resp)
	})
	ctrl := startTCP(t, h)

	ex, err := acidns.NewTCPExchanger(ctrl.Addr())
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), mkQuery(t, "example.com", rrtype.A))
	require.NoError(t, err)
	require.Equal(t, 1, len(resp.Answers()))
	require.Equal(t, "203.0.113.88", resp.Answers()[0].RData().(rdata.A).Addr().String())
}

func TestTCPServerShutdown(t *testing.T) {
	t.Parallel()
	srv, err := acidns.NewTCPServer(netip.MustParseAddrPort("127.0.0.1:0"),
		acidns.HandlerFunc(func(_ context.Context, _ acidns.ResponseWriter, _ wire.Message) {}))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	ctrl, err := srv.Run(ctx)
	require.NoError(t, err)

	cancel()
	select {
	case <-ctrl.Done():
		require.NoError(t, ctrl.Err())
	case <-time.After(2 * time.Second):
		t.Fatal("server did not exit")
	}
}

// TestTCPServerOversizedBodyClosesConnection verifies that a length-prefix
// claiming more than WithTCPMaxMessageSize bytes causes the server to
// close the connection without ever allocating the body buffer.
// Without the cap, a hostile peer could force the server to allocate up
// to 64 KiB per simultaneous connection (the wire-format ceiling).
func TestTCPServerOversizedBodyClosesConnection(t *testing.T) {
	t.Parallel()
	h := acidns.HandlerFunc(func(_ context.Context, _ acidns.ResponseWriter, _ wire.Message) {})
	ctrl := startTCP(t, h, acidns.WithTCPMaxMessageSize(512))

	c, err := net.Dial("tcp", ctrl.Addr().String())
	require.NoError(t, err)
	defer c.Close()

	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], 1024) // > maxMessageSize
	_, err = c.Write(hdr[:])
	require.NoError(t, err)

	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	var buf [1]byte
	_, err = c.Read(buf[:])
	require.ErrorIs(t, err, io.EOF, "server must close on oversized claim")
}

// TestTCPServerCancelsHandlerOnShutdown verifies that the per-connection
// context derived inside serveConn is cancelled when the Serve context
// is cancelled, so an in-flight handler chasing a slow upstream sees
// ctx.Done() and can return promptly. Without this, Shutdown cannot
// reach a clean stop while a handler is still running.
func TestTCPServerCancelsHandlerOnShutdown(t *testing.T) {
	t.Parallel()
	started := make(chan struct{})
	cancelled := make(chan struct{}, 1)
	h := acidns.HandlerFunc(func(ctx context.Context, _ acidns.ResponseWriter, _ wire.Message) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-ctx.Done()
		select {
		case cancelled <- struct{}{}:
		default:
		}
	})

	srv, err := acidns.NewTCPServer(netip.MustParseAddrPort("127.0.0.1:0"), h)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	ctrl, err := srv.Run(ctx)
	require.NoError(t, err)

	c, err := net.Dial("tcp", ctrl.Addr().String())
	require.NoError(t, err)
	defer c.Close()

	q, _ := wire.NewBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	body, err := wire.Marshal(q)
	require.NoError(t, err)
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(body)))
	_, err = c.Write(hdr[:])
	require.NoError(t, err)
	_, err = c.Write(body)
	require.NoError(t, err)

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not start")
	}

	cancel()

	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("handler context not cancelled on Serve shutdown")
	}
}

func TestTCPServerNoTruncation(t *testing.T) {
	t.Parallel()

	h := acidns.HandlerFunc(func(_ context.Context, w acidns.ResponseWriter, q wire.Message) {
		b := wire.NewBuilder().
			ID(q.ID()).
			Response(true).
			Question(q.Questions()[0])
		long := make([]byte, 200)
		for i := range long {
			long[i] = 'X'
		}
		txt, _ := rdata.NewTXT(string(long))
		for range 50 {
			b = b.Answer(wire.NewRecord(q.Questions()[0].Name(), time.Minute, txt))
		}
		resp, _ := b.Build()
		_ = w.WriteMsg(resp)
	})
	ctrl := startTCP(t, h)

	ex, err := acidns.NewTCPExchanger(ctrl.Addr())
	require.NoError(t, err)

	q, _ := wire.NewBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.TXT)).
		Build()
	resp, err := ex.Exchange(t.Context(), q)
	require.NoError(t, err)
	require.False(t, resp.Flags().Truncated())
	require.Equal(t, 50, len(resp.Answers()))
}
