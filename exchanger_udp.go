package acidns

// UDP exchanger: a Datagram-style DNS Exchanger over UDP.
//
// It performs a single send and reads datagrams until one whose ID matches
// the request is received, the context fires, or an unrecoverable I/O error
// occurs. It does NOT retry on truncation; callers wanting TCP fall-back are
// expected to compose two transports at the resolver layer.
//
// # Option naming
//
// Client-side options live on [UDPClientOption]; server-side options on
// [UDPListenerOption] (see server_udp.go). The two are prefixed
// `UDPClient*` / `UDPListener*` ONLY when the same concept exists on
// both sides — for example [WithUDPClientBufferSize] vs
// [WithUDPListenerBufferSize]. Concepts unique to one side use the
// plain name ([WithUDPTimeout] is client-only; [WithUDPWriteTimeout],
// [WithUDPMaxResponse] etc. are listener-only and unambiguous).

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/option/v3"
)

// UDPClientOption configures a UDP Exchanger.
type UDPClientOption interface {
	option.Interface
	udpClientOption()
}

type udpClientOption struct{ option.Interface }

func (udpClientOption) udpClientOption() {}

type udpClientConfig struct {
	timeout    time.Duration
	bufferSize int
	use0x20    bool
}

type identUDPTimeout struct{}
type identUDPClientBufferSize struct{}
type identUDPCaseRandomization struct{}

// WithUDPTimeout sets a per-exchange timeout that takes effect when
// the caller supplies a context without its own deadline. Defaults
// to 5 seconds. Pass 0 to disable the fallback (the context deadline
// or kernel socket timeout becomes the only bound — typically what
// you want only in tests or with a hard ctx deadline).
func WithUDPTimeout(d time.Duration) UDPClientOption {
	return udpClientOption{option.New(identUDPTimeout{}, d)}
}

// WithUDPClientBufferSize sets the size of the UDP read buffer in bytes. Defaults
// to 4096, which fits a typical EDNS-extended response.
func WithUDPClientBufferSize(n int) UDPClientOption {
	return udpClientOption{option.New(identUDPClientBufferSize{}, n)}
}

// WithUDPCaseRandomization toggles RFC 5452 §9.3 "0x20" hardening:
// the exchanger randomly toggles the case of ASCII letters in the
// QNAME of every outbound query, then verifies the response's
// question section matches case-exactly. A spoofer that guesses the
// 16-bit transaction ID still has to reproduce the case pattern,
// raising the per-query search space by 2^N for an N-letter qname.
//
// Defaults to true so the safe behaviour is uniform across every
// construction path ([NewUDPClient] direct, [NewResolver] with
// [WithServers], [recursive.New]). Pass
// [WithUDPCaseRandomization](false) to opt out for upstreams known
// to silently lowercase the qname in responses (rare).
func WithUDPCaseRandomization(v bool) UDPClientOption {
	return udpClientOption{option.New(identUDPCaseRandomization{}, v)}
}

type UDPClient struct {
	addr    netip.AddrPort
	timeout time.Duration
	bufsize int
	use0x20 bool
}

// NewUDPClient returns a *UDPClient that talks UDP to addr.
// The concrete pointer is returned so callers can reach
// implementation-specific affordances (e.g. future Close, statistics)
// without an interface assertion; *UDPClient satisfies [Exchanger].
func NewUDPClient(addr netip.AddrPort, opts ...UDPClientOption) (*UDPClient, error) {
	if !addr.IsValid() {
		return nil, fmt.Errorf("%w: udp client server address", ErrInvalidAddress)
	}
	c := udpClientConfig{timeout: 5 * time.Second, bufferSize: 4096, use0x20: true}
	for _, o := range opts {
		switch o.Ident() {
		case identUDPTimeout{}:
			c.timeout = option.MustGet[time.Duration](o)
		case identUDPClientBufferSize{}:
			c.bufferSize = option.MustGet[int](o)
		case identUDPCaseRandomization{}:
			c.use0x20 = option.MustGet[bool](o)
		}
	}
	return &UDPClient{addr: addr, timeout: c.timeout, bufsize: c.bufferSize, use0x20: c.use0x20}, nil
}

func (e *UDPClient) Exchange(ctx context.Context, q wire.Message) (wire.Message, error) {
	msg, err := wire.Marshal(q)
	if err != nil {
		return wire.Message{}, fmt.Errorf("acidns: marshal query: %w", err)
	}
	// Pre-extract the sent question section so we can byte-compare
	// against the response's question section when 0x20 is on. The
	// case randomization happens after locating the question bytes
	// (the locator only needs the length byte structure, which case
	// flips don't affect).
	//
	// Skip 0x20 in three cases where it doesn't apply:
	//   1. No question section (preflight FORMERR tests, raw probes).
	//   2. Non-QUERY opcode — UPDATE / NOTIFY / DSO carry a structurally
	//      similar "zone" / "question" field but the spec doesn't require
	//      the response to echo it byte-exact, and UPDATE callers (e.g.
	//      [acidns.RawRequest] consumers asserting on the wire bytes)
	//      depend on the qname surviving unmolested.
	// Hardcoding the negative reason here is uglier than having callers
	// pass [WithUDPCaseRandomization](false), but the friendlier
	// default avoids a landmine for every UPDATE / NOTIFY user who
	// would otherwise have to know to opt out.
	var sentQuestion []byte
	use0x20 := e.use0x20 && len(q.Questions()) > 0 && q.Flags().Opcode() == wire.OpcodeQuery
	if use0x20 {
		qs, qerr := questionSectionBytes(msg)
		if qerr != nil {
			return wire.Message{}, fmt.Errorf("acidns: extract sent question: %w", qerr)
		}
		// Randomize case in-place on the qname portion of msg, then
		// snapshot the resulting question bytes so the inbound check
		// has the exact pattern we sent.
		if err := randomizeQNameCase(msg[12 : 12+len(qs)-4]); err != nil {
			return wire.Message{}, fmt.Errorf("acidns: 0x20 randomness: %w", err)
		}
		sentQuestion = append([]byte(nil), msg[12:12+len(qs)]...)
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", e.addr.String())
	if err != nil {
		return wire.Message{}, fmt.Errorf("acidns: dial %s: %w", e.addr, err)
	}
	defer func() { _ = conn.Close() }()

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else if e.timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(e.timeout))
	}

	// Close on ctx cancel so a blocked Read returns promptly.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-stop:
		}
	}()

	if _, err := conn.Write(msg); err != nil {
		return wire.Message{}, fmt.Errorf("acidns: write: %w", err)
	}

	buf := make([]byte, e.bufsize)
	// Bound how many invalid / spoofed datagrams we tolerate per
	// Exchange. A single combined cap (the previous shape) lets a
	// modest flood of forged datagrams race the legitimate response
	// and surface a fake "lame upstream" error to the recursive
	// resolver. Splitting per reason keeps the CPU bound while letting
	// a noisy network deliver the real answer:
	//
	//   - parseErr: malformed wire (incl. ICMP-driven garbage); benign
	//     noise should be small.
	//   - idMismatch: forged-or-stale ID. The 16-bit ID space is small
	//     enough that an attacker can fire many guesses cheaply, so
	//     keep this budget the loosest.
	//   - questionMismatch / caseMismatch: ID matched but question
	//     didn't echo correctly — extremely improbable for benign
	//     noise, looser-than-strict to swallow spurious bursts but
	//     still bounded.
	const (
		maxParseErr         = 16
		maxIDMismatch       = 256
		maxQuestionMismatch = 16
		maxCaseMismatch     = 16
	)
	var parseErr, idMis, qMis, caseMis int
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return wire.Message{}, cerr
			}
			return wire.Message{}, fmt.Errorf("acidns: read: %w", err)
		}
		if cerr := ctx.Err(); cerr != nil {
			return wire.Message{}, cerr
		}
		resp, err := wire.Unmarshal(buf[:n])
		if err != nil {
			parseErr++
			if parseErr >= maxParseErr {
				return wire.Message{}, fmt.Errorf("acidns: parse-error budget exhausted: %w", err)
			}
			continue
		}
		if resp.ID() != q.ID() {
			idMis++
			if idMis >= maxIDMismatch {
				return wire.Message{}, fmt.Errorf("acidns: id-mismatch budget exhausted")
			}
			continue
		}
		if !wire.QuestionsMatch(q, resp) {
			qMis++
			if qMis >= maxQuestionMismatch {
				return wire.Message{}, fmt.Errorf("acidns: question-mismatch budget exhausted")
			}
			continue
		}
		if use0x20 {
			recvQuestion, qerr := questionSectionBytes(buf[:n])
			if qerr != nil || !bytes.Equal(recvQuestion, sentQuestion) {
				caseMis++
				if caseMis >= maxCaseMismatch {
					return wire.Message{}, fmt.Errorf("acidns: 0x20-mismatch budget exhausted")
				}
				continue
			}
		}
		return resp, nil
	}
}

// randomizeQNameCase walks the qname bytes (length-prefixed labels
// terminated by a zero byte) and flips a random subset of ASCII
// letters to upper case. Only bytes inside label payloads are
// touched; length octets and the terminator stay intact. The wire
// layer canonicalises decoded names to lowercase, so on entry every
// letter byte is 'a'-'z' — we either leave it or transform to
// 'A'-'Z'.
//
// The bitstream comes from crypto/rand. A predictable PRNG would
// let an off-path attacker who has observed several outbound
// queries from the same process reconstruct the RNG state and
// predict subsequent case patterns, defeating 0x20 exactly when it
// matters most. The cost is one read of (qname_len/8) bytes from
// the OS RNG per query — negligible against the UDP syscall.
func randomizeQNameCase(qname []byte) error {
	// At most one bit per byte; preallocate a comfortable upper
	// bound so we never run short during the walk.
	bits := make([]byte, (len(qname)+7)/8)
	if _, err := rand.Read(bits); err != nil {
		return err
	}
	bitIdx := 0
	off := 0
	for off < len(qname) {
		l := int(qname[off])
		if l == 0 {
			return nil
		}
		if l&0xc0 != 0 {
			return nil // pointer — should not occur in question section
		}
		off++
		end := off + l
		if end > len(qname) {
			return nil
		}
		for i := off; i < end; i++ {
			b := qname[i]
			if b < 'a' || b > 'z' {
				continue
			}
			byteIdx := bitIdx / 8
			if byteIdx >= len(bits) {
				return nil
			}
			if bits[byteIdx]&(1<<(bitIdx%8)) != 0 {
				qname[i] = b - 32
			}
			bitIdx++
		}
		off = end
	}
	return nil
}

// questionSectionBytes returns msg[12 : start_of_answer_section] —
// the wire bytes covering the single question (qname + qtype +
// qclass). Used for byte-exact comparison of the question section
// (case-sensitive 0x20 verification, RFC 5452 §9.3).
//
// RFC 1035 §4.1.2 forbids compression pointers in the question
// because the question is the first name in the message and has no
// prior name to point to. A peer that emits a pointer here is
// non-conformant and we reject by surfacing an error.
func questionSectionBytes(msg []byte) ([]byte, error) {
	if len(msg) < 12 {
		return nil, fmt.Errorf("message shorter than DNS header")
	}
	off := 12
	for {
		if off >= len(msg) {
			return nil, fmt.Errorf("truncated qname in question")
		}
		l := int(msg[off])
		if l == 0 {
			off++
			break
		}
		if l&0xc0 != 0 {
			return nil, fmt.Errorf("compression pointer in question section")
		}
		off += 1 + l
	}
	if off+4 > len(msg) {
		return nil, fmt.Errorf("truncated question fields")
	}
	return msg[12 : off+4], nil
}
