package acidns_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// recordingHandler counts ServeDNS invocations so the preflight tests
// can assert that filtered packets never reach the handler.
type recordingHandler struct {
	hits atomic.Int32
}

func (r *recordingHandler) ServeDNS(_ context.Context, w acidns.ResponseWriter, q wire.Message) {
	r.hits.Add(1)
	b := wire.NewBuilder().ID(q.ID()).Response(true)
	for _, qq := range q.Questions() {
		b = b.Question(qq)
	}
	resp, _ := b.Build()
	_ = w.WriteMsg(resp)
}

// TestPreflightDropsQRSetOnUDP verifies the framework silently drops
// inbound UDP datagrams with QR=1 and never invokes the handler. RFC
// 5452 §6 — only queries belong on the server-side socket.
func TestPreflightDropsQRSetOnUDP(t *testing.T) {
	t.Parallel()
	h := &recordingHandler{}
	ctrl, _ := startUDP(t, h)

	resp, err := wire.NewBuilder().
		ID(0xbeef).
		Response(true).
		Question(wire.NewQuestion(wire.MustParseName("a.test."), rrtype.A)).
		Build()
	require.NoError(t, err)
	buf, err := wire.Marshal(resp)
	require.NoError(t, err)

	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(ctrl.Addr()))
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	_, err = conn.Write(buf)
	require.NoError(t, err)

	// Expect no reply — read should time out.
	_ = conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	rb := make([]byte, 1024)
	_, err = conn.Read(rb)
	var ne net.Error
	require.True(t, errors.As(err, &ne) && ne.Timeout(), "expected read timeout, got %v", err)
	require.Equal(t, int32(0), h.hits.Load(), "handler must not see QR=1 datagrams")
}

// TestPreflightFormErrOnZeroQuestionsUDP verifies the framework synthesises
// a FORMERR for QDCOUNT=0 QUERY messages and does not invoke the handler.
func TestPreflightFormErrOnZeroQuestionsUDP(t *testing.T) {
	t.Parallel()
	h := &recordingHandler{}
	ctrl, _ := startUDP(t, h)

	q, err := wire.NewBuilder().ID(0x4242).RecursionDesired(true).Build()
	require.NoError(t, err)
	ex, err := acidns.NewUDPExchanger(ctrl.Addr())
	require.NoError(t, err)
	qctx, qcancel := context.WithTimeout(t.Context(), time.Second)
	defer qcancel()
	resp, err := ex.Exchange(qctx, q)
	require.NoError(t, err)
	require.True(t, resp.Flags().Response())
	require.Equal(t, wire.RCODEFormErr, resp.Flags().RCODE())
	require.Equal(t, int32(0), h.hits.Load(), "handler must not see QDCOUNT=0 messages")
}

// TestPreflightFormErrClampsUDPSize verifies that a peer-supplied
// EDNS UDPSize is clamped to the project default (1232) in the FORMERR
// reply, so a misbehaving or malicious peer cannot have us echo an
// inflated value (e.g. 65535) that downstream caches might otherwise
// trust.
func TestPreflightFormErrClampsUDPSize(t *testing.T) {
	t.Parallel()
	h := &recordingHandler{}
	ctrl, _ := startUDP(t, h)

	ed, err := wire.NewEDNSBuilder().UDPSize(65535).Build()
	require.NoError(t, err)
	q, err := wire.NewBuilder().
		ID(0x4243).
		RecursionDesired(true).
		EDNS(ed).
		Build()
	require.NoError(t, err)

	ex, err := acidns.NewUDPExchanger(ctrl.Addr())
	require.NoError(t, err)
	qctx, qcancel := context.WithTimeout(t.Context(), time.Second)
	defer qcancel()
	resp, err := ex.Exchange(qctx, q)
	require.NoError(t, err)
	require.Equal(t, wire.RCODEFormErr, resp.Flags().RCODE())

	respE, ok := resp.EDNS()
	require.True(t, ok, "FORMERR reply must echo OPT when request had one")
	require.LessOrEqual(t, respE.UDPSize(), uint16(1232),
		"FORMERR reply UDPSize must be clamped to <=1232")
	require.Equal(t, int32(0), h.hits.Load(), "handler must not see QDCOUNT=0 messages")
}

// TestPreflightAcceptsValidQuery sanity-checks that the preflight does
// NOT reject conformant queries.
func TestPreflightAcceptsValidQuery(t *testing.T) {
	t.Parallel()
	h := &recordingHandler{}
	ctrl, _ := startUDP(t, h)

	q := mkQuery(t, "a.test.", rrtype.A)
	ex, err := acidns.NewUDPExchanger(netip.AddrPortFrom(ctrl.Addr().Addr(), ctrl.Addr().Port()))
	require.NoError(t, err)
	qctx, qcancel := context.WithTimeout(t.Context(), time.Second)
	defer qcancel()
	_, err = ex.Exchange(qctx, q)
	require.NoError(t, err)
	require.Equal(t, int32(1), h.hits.Load())
}
