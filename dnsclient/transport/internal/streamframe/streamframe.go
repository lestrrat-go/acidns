// Package streamframe implements RFC 1035 §4.2.2 length-prefixed DNS
// framing over a stream connection. It is shared by the TCP and DoT
// transports; DoH uses HTTP and DoQ uses QUIC streams, neither of which
// reuses this code.
package streamframe

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/lestrrat-go/acidns/dnsmsg"
)

// Exchange performs a single length-prefixed request/response exchange over
// conn. The caller is responsible for dialing/handshaking; conn is closed
// before this function returns. Cancellation of ctx aborts a pending I/O
// by setting an immediate connection deadline.
func Exchange(ctx context.Context, conn net.Conn, q dnsmsg.Message, fallbackTimeout time.Duration) (dnsmsg.Message, error) {
	defer conn.Close()

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

	wire, err := dnsmsg.Marshal(q)
	if err != nil {
		return nil, fmt.Errorf("streamframe: marshal: %w", err)
	}
	if len(wire) > 0xffff {
		return nil, fmt.Errorf("streamframe: query too large (%d bytes)", len(wire))
	}

	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(wire)))
	if _, err := conn.Write(hdr[:]); err != nil {
		return nil, fmt.Errorf("streamframe: write length: %w", err)
	}
	if _, err := conn.Write(wire); err != nil {
		return nil, fmt.Errorf("streamframe: write body: %w", err)
	}

	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		return nil, fmt.Errorf("streamframe: read length: %w", err)
	}
	respLen := binary.BigEndian.Uint16(hdr[:])
	body := make([]byte, respLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		return nil, fmt.Errorf("streamframe: read body: %w", err)
	}
	resp, err := dnsmsg.Unmarshal(body)
	if err != nil {
		return nil, fmt.Errorf("streamframe: unmarshal: %w", err)
	}
	if resp.ID() != q.ID() {
		return nil, fmt.Errorf("streamframe: id mismatch: got %#x, want %#x", resp.ID(), q.ID())
	}
	return resp, nil
}
