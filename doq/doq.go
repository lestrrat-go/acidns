//go:build !acidns_no_doq

// Package doq implements DNS over Dedicated QUIC connections (RFC 9250).
//
// Each Exchange opens a fresh QUIC connection, opens one bidirectional
// stream, sends a length-prefixed query (RFC 9250 §4.2.1 — same msg
// framing as TCP), reads a length-prefixed response, then closes the
// stream and connection. Connection reuse and stream multiplexing are out
// of scope for this primitive transport.
//
// DoQ pulls quic-go (and its TLS / ECN / connection-migration code paths)
// into the binary. Builds that do not need DoQ can pass the
// `acidns_no_doq` build tag to compile a stub package that returns
// ErrDoQDisabled from New; this keeps the quic-go dependency out of the
// final binary.
package doq

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/internal/streamframe"
	"github.com/lestrrat-go/acidns/wire"
)

// alpn is the ALPN identifier registered for DoQ.
const alpn = "doq"

// Option configures a DoQ Exchanger.
type Option interface{ applyDoQ(*config) }

type optionFunc func(*config)

func (f optionFunc) applyDoQ(c *config) { f(c) }

type config struct {
	timeout    time.Duration
	tlsConfig  *tls.Config
	serverName string
}

// WithTimeout sets a per-exchange timeout used when ctx has no deadline.
func WithTimeout(d time.Duration) Option {
	return optionFunc(func(c *config) { c.timeout = d })
}

// WithTLSConfig overrides the default TLS configuration. The "doq" ALPN
// is added automatically if absent.
func WithTLSConfig(tc *tls.Config) Option {
	return optionFunc(func(c *config) { c.tlsConfig = tc.Clone() })
}

// WithServerName overrides SNI / certificate verification name.
func WithServerName(name string) Option {
	return optionFunc(func(c *config) { c.serverName = name })
}

type exchanger struct {
	addr      netip.AddrPort
	timeout   time.Duration
	tlsConfig *tls.Config
}

// New returns an Exchanger that talks DoQ to addr.
func New(addr netip.AddrPort, opts ...Option) (acidns.Exchanger, error) {
	if !addr.IsValid() {
		return nil, fmt.Errorf("doq: invalid server address")
	}
	c := config{timeout: 10 * time.Second}
	for _, o := range opts {
		o.applyDoQ(&c)
	}

	var tcfg *tls.Config
	if c.tlsConfig != nil {
		tcfg = c.tlsConfig.Clone()
	} else {
		tcfg = &tls.Config{MinVersion: tls.VersionTLS13}
	}
	if !containsALPN(tcfg.NextProtos, alpn) {
		tcfg.NextProtos = append(tcfg.NextProtos, alpn)
	}
	if c.serverName != "" {
		tcfg.ServerName = c.serverName
	} else if tcfg.ServerName == "" {
		tcfg.ServerName = addr.Addr().String()
	}

	return &exchanger{addr: addr, timeout: c.timeout, tlsConfig: tcfg}, nil
}

func containsALPN(list []string, want string) bool {
	return slices.Contains(list, want)
}

func (e *exchanger) Exchange(ctx context.Context, q wire.Message) (wire.Message, error) {
	msg, err := wire.Marshal(q)
	if err != nil {
		return nil, fmt.Errorf("doq: marshal: %w", err)
	}

	if _, ok := ctx.Deadline(); !ok && e.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.timeout)
		defer cancel()
	}

	conn, err := quic.DialAddr(ctx, e.addr.String(), e.tlsConfig, &quic.Config{
		MaxIdleTimeout: 30 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("doq: dial %s: %w", e.addr, err)
	}
	defer func() { _ = conn.CloseWithError(0, "") }()

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("doq: open stream: %w", err)
	}

	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(msg)))
	if _, err := stream.Write(hdr[:]); err != nil {
		return nil, fmt.Errorf("doq: write length: %w", err)
	}
	if _, err := stream.Write(msg); err != nil {
		return nil, fmt.Errorf("doq: write body: %w", err)
	}
	// RFC 9250 §4.2: client MUST send the FIN after the query body.
	if err := stream.Close(); err != nil {
		return nil, fmt.Errorf("doq: close write side: %w", err)
	}

	if _, err := io.ReadFull(stream, hdr[:]); err != nil {
		return nil, fmt.Errorf("doq: read length: %w", err)
	}
	respLen := binary.BigEndian.Uint16(hdr[:])
	body := make([]byte, respLen)
	if _, err := io.ReadFull(stream, body); err != nil {
		return nil, fmt.Errorf("doq: read body: %w", err)
	}

	resp, err := wire.Unmarshal(body)
	if err != nil {
		return nil, fmt.Errorf("doq: unmarshal: %w", err)
	}
	// RFC 9250 §4.2.1: query MUST set ID=0; response MUST set ID=0.
	// Many real-world servers echo the requested ID instead of mandating
	// zero. Validate either form.
	if resp.ID() != q.ID() && resp.ID() != 0 {
		return nil, fmt.Errorf("doq: id mismatch: got %#x", resp.ID())
	}
	return resp, nil
}

// Stream sends q on a fresh QUIC stream and returns a MessageStream from
// which the caller pulls responses. Implements XFR-over-QUIC (RFC 9103
// §4.4): one query, then a stream of responses on the same QUIC stream
// until the server FINs the read side.
func (e *exchanger) Stream(ctx context.Context, q wire.Message) (acidns.MessageStream, error) {
	dialCtx := ctx
	if _, ok := ctx.Deadline(); !ok && e.timeout > 0 {
		var cancel context.CancelFunc
		dialCtx, cancel = context.WithTimeout(ctx, e.timeout)
		defer cancel()
	}
	conn, err := quic.DialAddr(dialCtx, e.addr.String(), e.tlsConfig, &quic.Config{
		MaxIdleTimeout: 30 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("doq: dial %s: %w", e.addr, err)
	}
	stream, err := conn.OpenStreamSync(dialCtx)
	if err != nil {
		_ = conn.CloseWithError(0, "")
		return nil, fmt.Errorf("doq: open stream: %w", err)
	}
	if err := streamframe.WriteFrame(stream, q); err != nil {
		_ = conn.CloseWithError(0, "")
		return nil, fmt.Errorf("doq: %w", err)
	}
	// RFC 9250 §4.2: client MUST send the FIN after the query body. The
	// server then writes responses on the same stream until it FINs.
	if err := stream.Close(); err != nil {
		_ = conn.CloseWithError(0, "")
		return nil, fmt.Errorf("doq: close write side: %w", err)
	}
	return &doqStream{conn: conn, stream: stream, expectID: q.ID()}, nil
}

// doqStream wraps a single QUIC stream that has had a query written to it.
// Next reads response frames; Close cancels read on the stream and closes
// the parent connection.
type doqStream struct {
	conn      *quic.Conn
	stream    *quic.Stream
	expectID  uint16
	closeOnce sync.Once
}

func (s *doqStream) Next(ctx context.Context) (wire.Message, error) {
	if dl, ok := ctx.Deadline(); ok {
		_ = s.stream.SetReadDeadline(dl)
	}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = s.stream.SetReadDeadline(time.Now())
		case <-stop:
		}
	}()
	m, err := streamframe.ReadFrame(s.stream)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		return nil, err
	}
	if m.ID() != s.expectID && m.ID() != 0 {
		return nil, fmt.Errorf("doq: id mismatch: got %#x", m.ID())
	}
	return m, nil
}

func (s *doqStream) Close() error {
	s.closeOnce.Do(func() {
		s.stream.CancelRead(0)
		_ = s.conn.CloseWithError(0, "")
	})
	return nil
}
