package acidns

// UDP exchanger: a Datagram-style DNS Exchanger over UDP.
//
// It performs a single send and reads datagrams until one whose ID matches
// the request is received, the context fires, or an unrecoverable I/O error
// occurs. It does NOT retry on truncation; callers wanting TCP fall-back are
// expected to compose two transports at the resolver layer.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"time"

	"github.com/lestrrat-go/acidns/wire"
)

// UDPExchangerOption configures a UDP Exchanger.
type UDPExchangerOption interface{ applyUDPExchanger(*udpExchangerConfig) }

type udpExchangerOptionFunc func(*udpExchangerConfig)

func (f udpExchangerOptionFunc) applyUDPExchanger(c *udpExchangerConfig) { f(c) }

type udpExchangerConfig struct {
	timeout    time.Duration
	bufferSize int
	use0x20    bool
}

// WithUDPTimeout sets a per-exchange timeout that takes effect when the caller
// supplies a context without its own deadline. Defaults to 5 seconds.
func WithUDPTimeout(d time.Duration) UDPExchangerOption {
	return udpExchangerOptionFunc(func(c *udpExchangerConfig) { c.timeout = d })
}

// WithUDPReadBufferSize sets the size of the UDP read buffer in bytes. Defaults
// to 4096, which fits a typical EDNS-extended response.
func WithUDPReadBufferSize(n int) UDPExchangerOption {
	return udpExchangerOptionFunc(func(c *udpExchangerConfig) { c.bufferSize = n })
}

// WithUDP0x20 toggles RFC 5452 §9.3 0x20 hardening: the exchanger
// randomly toggles the case of ASCII letters in the QNAME of every
// outbound query, then verifies the response's question section
// matches case-exactly. A spoofer that guesses the 16-bit
// transaction ID still has to reproduce the case-pattern, raising
// the per-query search space by 2^N for an N-letter qname.
//
// Defaults to false at this raw-exchanger level so explicit callers
// can mix-and-match policies per server. The convenience
// constructors ([NewResolver] with [WithServers], [recursive.New])
// flip this on by default and expose a Without* opt-out for
// upstreams known to silently lowercase the qname in responses
// (rare).
func WithUDP0x20(v bool) UDPExchangerOption {
	return udpExchangerOptionFunc(func(c *udpExchangerConfig) { c.use0x20 = v })
}

type udpExchanger struct {
	addr    netip.AddrPort
	timeout time.Duration
	bufsize int
	use0x20 bool
}

// NewUDPExchanger returns an Exchanger that talks UDP to addr.
func NewUDPExchanger(addr netip.AddrPort, opts ...UDPExchangerOption) (Exchanger, error) {
	if !addr.IsValid() {
		return nil, fmt.Errorf("udp: invalid server address")
	}
	c := udpExchangerConfig{timeout: 5 * time.Second, bufferSize: 4096}
	for _, o := range opts {
		o.applyUDPExchanger(&c)
	}
	return &udpExchanger{addr: addr, timeout: c.timeout, bufsize: c.bufferSize, use0x20: c.use0x20}, nil
}

func (e *udpExchanger) Exchange(ctx context.Context, q wire.Message) (wire.Message, error) {
	msg, err := wire.Marshal(q)
	if err != nil {
		return nil, fmt.Errorf("udp: marshal query: %w", err)
	}
	// Pre-extract the sent question section so we can byte-compare
	// against the response's question section when 0x20 is on. The
	// case randomization happens after locating the question bytes
	// (the locator only needs the length byte structure, which case
	// flips don't affect).
	var sentQuestion []byte
	if e.use0x20 {
		qs, qerr := questionSectionBytes(msg)
		if qerr != nil {
			return nil, fmt.Errorf("udp: extract sent question: %w", qerr)
		}
		// Randomize case in-place on the qname portion of msg, then
		// snapshot the resulting question bytes so the inbound check
		// has the exact pattern we sent.
		randomizeQNameCase(msg[12 : 12+len(qs)-4])
		sentQuestion = append([]byte(nil), msg[12:12+len(qs)]...)
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", e.addr.String())
	if err != nil {
		return nil, fmt.Errorf("udp: dial %s: %w", e.addr, err)
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
		return nil, fmt.Errorf("udp: write: %w", err)
	}

	buf := make([]byte, e.bufsize)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return nil, cerr
			}
			return nil, fmt.Errorf("udp: read: %w", err)
		}
		resp, err := wire.Unmarshal(buf[:n])
		if err != nil {
			// Malformed datagrams are dropped silently per RFC 1035 §7.3
			// (server is misbehaving) — but only if there's still time.
			if errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return nil, ctx.Err()
			}
			continue
		}
		if resp.ID() != q.ID() {
			continue
		}
		if !wire.QuestionsMatch(q, resp) {
			// RFC 5452 §9.2: spoofed responses with a guessed ID still
			// have to match the question section. Drop and keep waiting
			// for a legit response.
			continue
		}
		if e.use0x20 {
			recvQuestion, qerr := questionSectionBytes(buf[:n])
			if qerr != nil || !bytes.Equal(recvQuestion, sentQuestion) {
				// 0x20 mismatch — response question's case doesn't
				// match what we sent. Treat as forgery; keep waiting.
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
// 'A'-'Z'. Each letter independently has 50% probability of being
// flipped (math/rand is sufficient — the security property is
// search-space size, not cryptographic unpredictability).
func randomizeQNameCase(qname []byte) {
	off := 0
	for off < len(qname) {
		l := int(qname[off])
		if l == 0 {
			return
		}
		if l&0xc0 != 0 {
			return // pointer — should not occur in question section
		}
		off++
		end := off + l
		if end > len(qname) {
			return
		}
		for i := off; i < end; i++ {
			b := qname[i]
			if b >= 'a' && b <= 'z' && randBit() {
				qname[i] = b - 32
			}
		}
		off = end
	}
}

// randBit returns a single random bit. Uses math/rand/v2 because
// the property 0x20 needs is "doubles the search space per letter"
// — unpredictability per query is enough; cryptographic-grade RNG
// is overkill and would slow every outbound query.
func randBit() bool {
	return rand.IntN(2) == 1
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
