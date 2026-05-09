package mdns_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/mdns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/wirebb"
	"github.com/stretchr/testify/require"
)

// fakePacketConn is an in-process net.PacketConn used to drive
// mdns.Browse without any actual multicast network.
type fakePacketConn struct {
	mu sync.Mutex
	// queued is the bytes that ReadFrom will return one at a time.
	queued [][]byte
	// readSignal blocks ReadFrom until a value is delivered or it's closed.
	readSignal chan struct{}

	writes [][]byte
	closed bool

	deadline     time.Time
	readDeadline time.Time
	writeErr     error
}

func newFakePacketConn() *fakePacketConn {
	return &fakePacketConn{readSignal: make(chan struct{}, 16)}
}

func (f *fakePacketConn) push(b []byte) {
	f.mu.Lock()
	f.queued = append(f.queued, b)
	f.mu.Unlock()
	select {
	case f.readSignal <- struct{}{}:
	default:
	}
}

func (f *fakePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		f.mu.Lock()
		if f.closed {
			f.mu.Unlock()
			return 0, nil, net.ErrClosed
		}
		if len(f.queued) > 0 {
			b := f.queued[0]
			f.queued = f.queued[1:]
			n := copy(p, b)
			f.mu.Unlock()
			return n, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353}, nil
		}
		dl := f.readDeadline
		if dl.IsZero() {
			dl = f.deadline
		}
		f.mu.Unlock()

		var timer *time.Timer
		var timeoutCh <-chan time.Time
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return 0, nil, &timeoutError{}
			}
			timer = time.NewTimer(d)
			timeoutCh = timer.C
		}
		select {
		case <-f.readSignal:
			if timer != nil {
				timer.Stop()
			}
		case <-timeoutCh:
			return 0, nil, &timeoutError{}
		}
	}
}

func (f *fakePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	c := append([]byte(nil), p...)
	f.writes = append(f.writes, c)
	return len(p), nil
}

func (f *fakePacketConn) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	// Wake any pending ReadFrom.
	select {
	case f.readSignal <- struct{}{}:
	default:
	}
	return nil
}

func (f *fakePacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353}
}

func (f *fakePacketConn) SetDeadline(t time.Time) error {
	f.mu.Lock()
	f.deadline = t
	// Per net.Conn docs, SetDeadline sets both read and write deadlines.
	f.readDeadline = t
	f.mu.Unlock()
	// Signal so any blocked ReadFrom re-evaluates.
	select {
	case f.readSignal <- struct{}{}:
	default:
	}
	return nil
}

func (f *fakePacketConn) SetReadDeadline(t time.Time) error {
	f.mu.Lock()
	f.readDeadline = t
	f.mu.Unlock()
	select {
	case f.readSignal <- struct{}{}:
	default:
	}
	return nil
}

func (f *fakePacketConn) SetWriteDeadline(_ time.Time) error { return nil }

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func canonicalBrowseResponse(t *testing.T) []byte {
	t.Helper()
	svcType := wire.MustParseName("_http._tcp.local")
	instance := wire.MustParseName("Test._http._tcp.local")
	host := wire.MustParseName("test.local")

	txt, err := rdata.NewTXT("foo=bar")
	require.NoError(t, err)
	srv := rdata.MustNewSRV(0, 0, 80, host)
	a := rdata.MustNewA(netip.MustParseAddr("192.0.2.10"))

	resp, err := wire.NewMessageBuilder().
		ID(0).
		Response(true).
		Answer(wire.NewRecord(svcType, time.Minute, rdata.MustNewPTR(instance))).
		Answer(wire.NewRecord(instance, time.Minute, srv)).
		Answer(wire.NewRecord(instance, time.Minute, txt)).
		Additional(wire.NewRecord(host, time.Minute, a)).
		Build()
	require.NoError(t, err)
	buf, err := wire.Marshal(resp)
	require.NoError(t, err)
	return buf
}

func withConn(pc net.PacketConn) mdns.BrowseOption {
	return mdns.WithBrowseConn(func() (net.PacketConn, error) { return pc, nil })
}

func TestBrowseSuccess(t *testing.T) {
	t.Parallel()
	pc := newFakePacketConn()
	pc.push(canonicalBrowseResponse(t))

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	services, err := mdns.Browse(ctx, "_http._tcp", withConn(pc))
	require.NoError(t, err)
	require.Equal(t, 1, len(services))
	require.Equal(t, "test", services[0].Instance())
	require.Equal(t, uint16(80), services[0].Port())
	require.Equal(t, "bar", services[0].Text()["foo"])

	// First write was the marshalled query.
	pc.mu.Lock()
	require.Equal(t, 1, len(pc.writes))
	pc.mu.Unlock()
	q, err := wire.Unmarshal(pc.writes[0])
	require.NoError(t, err)
	require.Equal(t, "_http._tcp.local.", q.Questions()[0].Name().String())
}

func TestBrowseNoResponse(t *testing.T) {
	t.Parallel()
	pc := newFakePacketConn()

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	_, err := mdns.Browse(ctx, "_http._tcp", withConn(pc))
	require.ErrorIs(t, err, mdns.ErrNoResponse)
}

func TestBrowseInvalidServiceName(t *testing.T) {
	t.Parallel()
	_, err := mdns.Browse(t.Context(), ".")
	require.ErrorIs(t, err, wirebb.ErrInvalidName)
}

func TestBrowseOpenError(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("boom")
	open := mdns.WithBrowseConn(func() (net.PacketConn, error) { return nil, wantErr })

	_, err := mdns.Browse(t.Context(), "_http._tcp", open)
	require.ErrorIs(t, err, wantErr)
}

func TestBrowseWriteError(t *testing.T) {
	t.Parallel()
	pc := newFakePacketConn()
	pc.writeErr = errors.New("write failed")

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	_, err := mdns.Browse(ctx, "_http._tcp", withConn(pc))
	require.ErrorContains(t, err, "write failed")
}

func TestBrowseIgnoresMalformedPackets(t *testing.T) {
	t.Parallel()
	pc := newFakePacketConn()
	// Garbage first, then a valid response.
	pc.push([]byte{0xff, 0xff, 0x00})
	pc.push(canonicalBrowseResponse(t))

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	services, err := mdns.Browse(ctx, "_http._tcp", withConn(pc))
	require.NoError(t, err)
	require.Equal(t, 1, len(services))
}

func TestBrowseContextCancelTriggersDeadline(t *testing.T) {
	t.Parallel()
	pc := newFakePacketConn()
	// Enqueue a real response so the call returns success once cancel
	// trips the deadline.
	pc.push(canonicalBrowseResponse(t))

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	services, err := mdns.Browse(ctx, "_http._tcp", withConn(pc))
	require.NoError(t, err)
	require.Equal(t, 1, len(services))
}

func TestBrowseContextDeadlineBeforeTimeout(t *testing.T) {
	t.Parallel()
	pc := newFakePacketConn()
	pc.push(canonicalBrowseResponse(t))

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	services, err := mdns.Browse(ctx, "_http._tcp", withConn(pc))
	require.NoError(t, err)
	require.Equal(t, 1, len(services))
}
