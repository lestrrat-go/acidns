// Package streamframe implements RFC 1035 §4.2.2 length-prefixed DNS
// framing over a stream connection. It is shared by the TCP, DoT, and DoQ
// transports; DoH uses HTTP framing and does not reuse this code.
package streamframe

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/lestrrat-go/acidns/wire"
)

// WriteFrame marshals m and writes it as a length-prefixed frame to w.
func WriteFrame(w io.Writer, m wire.Message) error {
	wire, err := wire.Marshal(m)
	if err != nil {
		return fmt.Errorf("streamframe: marshal: %w", err)
	}
	if len(wire) > 0xffff {
		return fmt.Errorf("streamframe: message too large (%d bytes)", len(wire))
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(wire)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("streamframe: write length: %w", err)
	}
	if _, err := w.Write(wire); err != nil {
		return fmt.Errorf("streamframe: write body: %w", err)
	}
	return nil
}

// ReadFrame reads the next length-prefixed frame from r and returns the
// unmarshaled message. Returns io.EOF if r reaches end-of-file before any
// length bytes are read; an EOF mid-frame is reported as io.ErrUnexpectedEOF.
func ReadFrame(r io.Reader) (wire.Message, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		// Translate the "no bytes" case to a clean io.EOF; other shapes
		// (partial header) become ErrUnexpectedEOF — io.ReadFull's contract.
		return nil, err
	}
	body := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err := io.ReadFull(r, body); err != nil {
		if err == io.EOF {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, fmt.Errorf("streamframe: read body: %w", err)
	}
	m, err := wire.Unmarshal(body)
	if err != nil {
		return nil, fmt.Errorf("streamframe: unmarshal: %w", err)
	}
	return m, nil
}

// Exchange performs a single length-prefixed request/response exchange over
// conn. The caller is responsible for dialing/handshaking; conn is closed
// before this function returns. Cancellation of ctx aborts a pending I/O by
// setting an immediate connection deadline.
func Exchange(ctx context.Context, conn net.Conn, q wire.Message, fallbackTimeout time.Duration) (wire.Message, error) {
	defer func() { _ = conn.Close() }()

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else if fallbackTimeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(fallbackTimeout))
	}

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-stop:
		}
	}()

	if err := WriteFrame(conn, q); err != nil {
		return nil, err
	}
	resp, err := ReadFrame(conn)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		return nil, err
	}
	if resp.ID() != q.ID() {
		return nil, fmt.Errorf("streamframe: id mismatch: got %#x, want %#x", resp.ID(), q.ID())
	}
	if !wire.QuestionsMatch(q, resp) {
		return nil, fmt.Errorf("streamframe: response question does not match request")
	}
	return resp, nil
}

// ConnStream wraps a net.Conn over which a streaming query has already been
// sent. Each Next call reads one length-prefixed response message; io.EOF
// is returned when the peer closes the connection cleanly between frames.
//
// Callers MUST Close the stream — including on error and after EOF — to
// release the underlying connection.
type ConnStream struct {
	conn      net.Conn
	expect    uint16
	stop      chan struct{}
	stopOnce  sync.Once
	closeOnce sync.Once
}

// NewConnStream sets the conn deadline (from ctx or fallbackTimeout), spins
// up a goroutine that bumps the deadline if ctx is cancelled, sends q as a
// length-prefixed frame, and returns a ConnStream ready for Next().
//
// On error the conn is closed before NewConnStream returns.
func NewConnStream(ctx context.Context, conn net.Conn, q wire.Message, fallbackTimeout time.Duration) (*ConnStream, error) {
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else if fallbackTimeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(fallbackTimeout))
	}
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-stop:
		}
	}()
	if err := WriteFrame(conn, q); err != nil {
		close(stop)
		_ = conn.Close()
		return nil, err
	}
	return &ConnStream{conn: conn, expect: q.ID(), stop: stop}, nil
}

// Next reads the next response frame. ctx cancellation is honored by
// bumping the conn deadline.
func (s *ConnStream) Next(ctx context.Context) (wire.Message, error) {
	if dl, ok := ctx.Deadline(); ok {
		_ = s.conn.SetDeadline(dl)
	}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = s.conn.SetDeadline(time.Now())
		case <-stop:
		}
	}()

	m, err := ReadFrame(s.conn)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		return nil, err
	}
	if m.ID() != s.expect {
		return nil, fmt.Errorf("streamframe: id mismatch: got %#x, want %#x", m.ID(), s.expect)
	}
	return m, nil
}

// Close releases the underlying connection. Idempotent.
func (s *ConnStream) Close() error {
	s.stopOnce.Do(func() { close(s.stop) })
	var err error
	s.closeOnce.Do(func() { err = s.conn.Close() })
	return err
}
