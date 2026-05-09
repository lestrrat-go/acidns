package acidns_test

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// TestUDP0x20RandomizesAndVerifies spins up a fake UDP responder
// that captures the qname bytes and either echoes them back
// (preserving case) or lowercases them (simulating a non-conformant
// peer). The 0x20-enabled exchanger MUST accept the case-preserving
// peer and reject the case-mangling peer.
func TestUDP0x20RandomizesAndVerifies(t *testing.T) {
	t.Parallel()

	t.Run("preserved", func(t *testing.T) {
		t.Parallel()
		addr := startCaseEchoServer(t, true /* preserve case */)
		ex, err := acidns.NewUDPExchanger(addr, acidns.WithUDP0x20(true))
		require.NoError(t, err)
		q := mkUDPQuery(t, "case.test.")
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		_, err = ex.Exchange(ctx, q)
		require.NoError(t, err)
	})

	t.Run("mangled", func(t *testing.T) {
		t.Parallel()
		addr := startCaseEchoServer(t, false /* lowercase the qname */)
		ex, err := acidns.NewUDPExchanger(addr,
			acidns.WithUDP0x20(true),
			acidns.WithUDPTimeout(500*time.Millisecond),
		)
		require.NoError(t, err)
		q := mkUDPQuery(t, "case.test.")
		ctx, cancel := context.WithTimeout(t.Context(), 1*time.Second)
		defer cancel()
		_, err = ex.Exchange(ctx, q)
		require.Error(t, err) // dropped + timed out waiting for a legit response
	})
}

// TestUDP0x20OutboundHasMixedCase checks that the exchanger
// actually flips letter case in the outbound qname bytes — a 0
// flip-rate would defeat the security property even if the
// inbound check passed.
func TestUDP0x20OutboundHasMixedCase(t *testing.T) {
	t.Parallel()
	captured := make(chan []byte, 64)
	addr := startQNameCaptureServer(t, captured)

	ex, err := acidns.NewUDPExchanger(addr, acidns.WithUDP0x20(true))
	require.NoError(t, err)

	const trials = 16
	const qname = "abcdefghijklmnop.test." // 16 letter labels — plenty of entropy
	sawUpper := false
	for range trials {
		q := mkUDPQuery(t, qname)
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		_, _ = ex.Exchange(ctx, q)
		cancel()
		select {
		case body := <-captured:
			for _, b := range body {
				if b >= 'A' && b <= 'Z' {
					sawUpper = true
					break
				}
			}
		default:
		}
		if sawUpper {
			break
		}
	}
	require.True(t, sawUpper,
		"0x20 must flip at least one letter to upper case across %d trials", trials)
}

func mkUDPQuery(t *testing.T, qname string) wire.Message {
	t.Helper()
	q, err := wire.NewBuilder().
		ID(0x1234).
		RecursionDesired(true).
		Question(wire.NewQuestion(wire.MustParseName(qname), rrtype.A)).
		Build()
	require.NoError(t, err)
	return q
}

// startCaseEchoServer answers every received query with a single A
// record. If preserveCase is true, the response echoes the request's
// question section bytes verbatim. Otherwise, the question is
// re-emitted with the qname lowercased — simulating a non-conformant
// peer that silently destroys 0x20 hardening.
func startCaseEchoServer(t *testing.T, preserveCase bool) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		for {
			buf := make([]byte, 4096)
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			body := buf[:n]
			req, err := wire.Unmarshal(body)
			if err != nil {
				continue
			}
			qq := req.Questions()[0]
			respMsg, _ := wire.NewBuilder().
				ID(req.ID()).
				Response(true).
				Question(qq).
				Answer(wire.NewRecord(qq.Name(), time.Minute,
					rdata.NewA(netip.MustParseAddr("203.0.113.1")))).
				Build()
			respBytes, _ := wire.Marshal(respMsg)

			if preserveCase {
				// Replace the marshaled response's question section
				// with the request's bytes (which include the case the
				// requester sent).
				if rqs := questionSpan(body); rqs > 12 {
					if rps := questionSpan(respBytes); rps == rqs {
						copy(respBytes[12:rqs], body[12:rqs])
					}
				}
			}
			_, _ = pc.WriteTo(respBytes, src)
		}
	}()
	la := pc.LocalAddr().(*net.UDPAddr)
	return netip.AddrPortFrom(la.AddrPort().Addr(), uint16(la.Port))
}

// startQNameCaptureServer captures the qname bytes of every received
// query and posts them on the supplied channel; never replies, so
// the exchanger times out (which is fine — we only care about what
// was sent).
func startQNameCaptureServer(t *testing.T, ch chan<- []byte) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		for {
			buf := make([]byte, 4096)
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			qs := questionSpan(buf[:n])
			if qs <= 12 {
				continue
			}
			cp := make([]byte, qs-12)
			copy(cp, buf[12:qs])
			select {
			case ch <- cp:
			default:
			}
		}
	}()
	la := pc.LocalAddr().(*net.UDPAddr)
	return netip.AddrPortFrom(la.AddrPort().Addr(), uint16(la.Port))
}

// questionSpan returns the byte offset just after the qname's
// trailing zero label, plus 4 bytes for qtype + qclass — i.e., the
// end-exclusive offset of the question section.
func questionSpan(msg []byte) int {
	if len(msg) < 12 {
		return 0
	}
	off := 12
	for off < len(msg) {
		l := int(msg[off])
		if l == 0 {
			off++
			break
		}
		if l&0xc0 != 0 {
			return 0
		}
		off += 1 + l
	}
	if off+4 > len(msg) {
		return 0
	}
	return off + 4
}

// silence linter on unused imports we only need for the helpers
var (
	_ = io.EOF
	_ = binary.BigEndian
	_ = strings.ToLower
)
