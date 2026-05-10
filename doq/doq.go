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
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/option/v3"
)

// alpn is the ALPN identifier registered for DoQ.
const alpn = "doq"

// RFC 9250 §4.3 error codes. The same numeric space is used for QUIC
// connection-level (ApplicationErrorCode) and stream-level
// (StreamErrorCode) closes; quic-go gives them distinct Go types so we
// declare each set separately.
const (
	doqNoError          quic.ApplicationErrorCode = 0x0
	doqInternalError    quic.ApplicationErrorCode = 0x1
	doqProtocolError    quic.ApplicationErrorCode = 0x2
	doqRequestCancelled quic.ApplicationErrorCode = 0x3
	doqExcessiveLoad    quic.ApplicationErrorCode = 0x4
	doqUnspecifiedError quic.ApplicationErrorCode = 0x5
)

const (
	doqStreamProtocolError    quic.StreamErrorCode = 0x2
	doqStreamRequestCancelled quic.StreamErrorCode = 0x3
)

type exchanger struct {
	addr             netip.AddrPort
	timeout          time.Duration
	tlsConfig        *tls.Config
	padding          bool
	maxResponseBytes int
}

// New returns an Exchanger that talks DoQ to addr.
func New(addr netip.AddrPort, opts ...Option) (acidns.Exchanger, error) {
	if !addr.IsValid() {
		return nil, ErrInvalidAddress
	}
	c := config{timeout: 10 * time.Second, padding: true, maxResponseBytes: DefaultMaxResponseBytes}
	for _, o := range opts {
		switch o.Ident() {
		case identTimeout{}:
			c.timeout = option.MustGet[time.Duration](o)
		case identTLSConfig{}:
			c.tlsConfig = option.MustGet[*tls.Config](o)
		case identServerName{}:
			c.serverName = option.MustGet[string](o)
		case identPadding{}:
			c.padding = option.MustGet[bool](o)
		case identMaxResponseBytes{}:
			c.maxResponseBytes = option.MustGet[int](o)
		case identInsecure{}:
			c.insecure = option.MustGet[bool](o)
		}
	}

	var tcfg *tls.Config
	if c.tlsConfig != nil {
		tcfg = c.tlsConfig.Clone()
	} else {
		tcfg = &tls.Config{MinVersion: tls.VersionTLS13}
	}
	// RFC 9250 §3: DoQ is TLS 1.3 only. A caller-supplied tls.Config
	// could otherwise lower MinVersion and silently negotiate
	// something the spec forbids — quic-go itself rejects sub-1.3
	// handshakes, but the explicit floor makes the intent loud.
	if tcfg.MinVersion < tls.VersionTLS13 {
		tcfg.MinVersion = tls.VersionTLS13
	}
	if !containsALPN(tcfg.NextProtos, alpn) {
		tcfg.NextProtos = append(tcfg.NextProtos, alpn)
	}
	if c.serverName != "" {
		tcfg.ServerName = c.serverName
	}
	// IP-literal address with no ServerName: refuse, mirroring [dot.New].
	// Authenticating a TLS handshake against an IP-as-SNI is a footgun.
	// WithInsecure callers opt out of cert verification entirely so
	// the SNI requirement no longer protects anything.
	if tcfg.ServerName == "" && !c.insecure {
		return nil, fmt.Errorf("%w (or *tls.Config.ServerName)", ErrServerNameRequired)
	}
	if c.insecure {
		tcfg.InsecureSkipVerify = true
	}

	mr := c.maxResponseBytes
	if mr <= 0 {
		mr = DefaultMaxResponseBytes
	}
	return &exchanger{addr: addr, timeout: c.timeout, tlsConfig: tcfg, padding: c.padding, maxResponseBytes: mr}, nil
}

func containsALPN(list []string, want string) bool {
	return slices.Contains(list, want)
}

func (e *exchanger) Exchange(ctx context.Context, q wire.Message) (wire.Message, error) {
	if e.padding {
		q = wire.PadEncrypted(q)
	}
	msg, err := wire.Marshal(q)
	if err != nil {
		return wire.Message{}, fmt.Errorf("doq: marshal: %w", err)
	}
	// RFC 9250 §4.2.1: the message ID on the wire MUST be 0. Multiplexing
	// happens via the QUIC stream, not the DNS ID, so a non-zero ID here
	// is a spec violation regardless of what q carries.
	msg[0] = 0
	msg[1] = 0

	if _, ok := ctx.Deadline(); !ok && e.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.timeout)
		defer cancel()
	}

	conn, err := quic.DialAddr(ctx, e.addr.String(), e.tlsConfig, &quic.Config{
		MaxIdleTimeout: 30 * time.Second,
		// RFC 9250 §4.5 forbids 0-RTT for DNS UPDATE; even for queries the
		// replay surface (cache-bust, amplification) is undesirable. Disable
		// explicitly so an upstream quic-go default flip cannot enable it.
		Allow0RTT: false,
	})
	if err != nil {
		return wire.Message{}, fmt.Errorf("doq: dial %s: %w", e.addr, err)
	}
	defer func() { _ = conn.CloseWithError(doqNoError, "") }()

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return wire.Message{}, fmt.Errorf("doq: open stream: %w", err)
	}

	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(msg)))
	if _, err := stream.Write(hdr[:]); err != nil {
		return wire.Message{}, fmt.Errorf("doq: write length: %w", err)
	}
	if _, err := stream.Write(msg); err != nil {
		return wire.Message{}, fmt.Errorf("doq: write body: %w", err)
	}
	// RFC 9250 §4.2: client MUST send the FIN after the query body.
	if err := stream.Close(); err != nil {
		return wire.Message{}, fmt.Errorf("doq: close write side: %w", err)
	}

	if _, err := io.ReadFull(stream, hdr[:]); err != nil {
		return wire.Message{}, fmt.Errorf("doq: read length: %w", err)
	}
	respLen := int(binary.BigEndian.Uint16(hdr[:]))
	if respLen > e.maxResponseBytes {
		return wire.Message{}, fmt.Errorf("%w: %d > %d", ErrResponseTooLarge, respLen, e.maxResponseBytes)
	}
	body := make([]byte, respLen)
	if _, err := io.ReadFull(stream, body); err != nil {
		return wire.Message{}, fmt.Errorf("doq: read body: %w", err)
	}
	return decodeDoQResponse(body, q)
}

// decodeDoQResponse validates RFC 9250 §4.2.1 (wire ID MUST be 0) and
// the response's question section against the request's, then restores
// the caller's requested ID on the parsed message so higher layers
// (resolver, retry logic) keying on Message.ID see the value they sent.
// The on-the-wire ID is intentionally lost to callers — DoQ multiplexes
// via QUIC streams, not via DNS IDs.
func decodeDoQResponse(body []byte, q wire.Message) (wire.Message, error) {
	if len(body) < 2 {
		return wire.Message{}, fmt.Errorf("doq: response too short")
	}
	if got := binary.BigEndian.Uint16(body[0:2]); got != 0 {
		return wire.Message{}, fmt.Errorf("doq: response ID must be 0 per RFC 9250 §4.2.1, got %#x", got)
	}
	binary.BigEndian.PutUint16(body[0:2], q.ID())
	resp, err := wire.Unmarshal(body)
	if err != nil {
		return wire.Message{}, fmt.Errorf("doq: unmarshal: %w", err)
	}
	if !wire.QuestionsMatch(q, resp) {
		return wire.Message{}, fmt.Errorf("doq: response question does not match request")
	}
	return resp, nil
}

// Stream sends q on a fresh QUIC stream and returns a MessageStream from
// which the caller pulls responses. Implements XFR-over-QUIC (RFC 9103
// §4.4): one query, then a stream of responses on the same QUIC stream
// until the server FINs the read side.
func (e *exchanger) Stream(ctx context.Context, q wire.Message) (acidns.MessageStream, error) {
	if e.padding {
		q = wire.PadEncrypted(q)
	}
	dialCtx := ctx
	if _, ok := ctx.Deadline(); !ok && e.timeout > 0 {
		var cancel context.CancelFunc
		dialCtx, cancel = context.WithTimeout(ctx, e.timeout)
		defer cancel()
	}
	conn, err := quic.DialAddr(dialCtx, e.addr.String(), e.tlsConfig, &quic.Config{
		MaxIdleTimeout: 30 * time.Second,
		Allow0RTT:      false,
	})
	if err != nil {
		return nil, fmt.Errorf("doq: dial %s: %w", e.addr, err)
	}
	stream, err := conn.OpenStreamSync(dialCtx)
	if err != nil {
		_ = conn.CloseWithError(doqInternalError, "")
		return nil, fmt.Errorf("doq: open stream: %w", err)
	}
	// Force ID=0 per RFC 9250 §4.2.1 by re-marshalling and patching the
	// header in place; we cannot use streamframe.WriteFrame because it
	// would marshal q's original ID.
	qBytes, err := wire.Marshal(q)
	if err != nil {
		_ = conn.CloseWithError(doqInternalError, "")
		return nil, fmt.Errorf("doq: marshal: %w", err)
	}
	qBytes[0] = 0
	qBytes[1] = 0
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(qBytes)))
	if _, err := stream.Write(hdr[:]); err != nil {
		_ = conn.CloseWithError(doqInternalError, "")
		return nil, fmt.Errorf("doq: write length: %w", err)
	}
	if _, err := stream.Write(qBytes); err != nil {
		_ = conn.CloseWithError(doqInternalError, "")
		return nil, fmt.Errorf("doq: write body: %w", err)
	}
	// RFC 9250 §4.2: client MUST send the FIN after the query body. The
	// server then writes responses on the same stream until it FINs.
	if err := stream.Close(); err != nil {
		_ = conn.CloseWithError(doqInternalError, "")
		return nil, fmt.Errorf("doq: close write side: %w", err)
	}
	return &doqStream{conn: conn, stream: stream, query: q}, nil
}

// doqStream wraps a single QUIC stream that has had a query written to it.
// Next reads response frames; Close cancels read on the stream and closes
// the parent connection.
type doqStream struct {
	conn      *quic.Conn
	stream    *quic.Stream
	query     wire.Message
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
	body, err := readDoQFrameBytes(s.stream)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return wire.Message{}, cerr
		}
		return wire.Message{}, err
	}
	return decodeDoQResponse(body, s.query)
}

// readDoQFrameBytes reads a length-prefixed DoQ response frame and
// returns the raw body so [decodeDoQResponse] can validate the wire ID
// before [wire.Unmarshal] runs. Sharing [streamframe.ReadFrame] would
// give us a parsed Message that already carries the (zero) wire ID,
// losing the chance to patch it back to the caller's value.
func readDoQFrameBytes(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	body := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("doq: read body: %w", err)
	}
	return body, nil
}

func (s *doqStream) Close() error {
	s.closeOnce.Do(func() {
		s.stream.CancelRead(doqStreamRequestCancelled)
		_ = s.conn.CloseWithError(doqNoError, "")
	})
	return nil
}
