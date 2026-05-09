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

func startTCPEcho(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				var lenBuf [2]byte
				if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
					return
				}
				size := binary.BigEndian.Uint16(lenBuf[:])
				body := make([]byte, size)
				if _, err := io.ReadFull(c, body); err != nil {
					return
				}
				req, err := wire.Unmarshal(body)
				if err != nil {
					return
				}
				resp, err := wire.NewBuilder().
					ID(req.ID()).
					Response(true).
					RecursionAvailable(true).
					Question(req.Questions()[0]).
					Answer(wire.NewRecord(req.Questions()[0].Name(), 60*time.Second,
						rdata.MustNewA(netip.MustParseAddr("203.0.113.5")))).
					Build()
				if err != nil {
					return
				}
				wire, err := wire.Marshal(resp)
				if err != nil {
					return
				}
				binary.BigEndian.PutUint16(lenBuf[:], uint16(len(wire)))
				_, _ = c.Write(lenBuf[:])
				_, _ = c.Write(wire)
			}(conn)
		}
	}()
	a := ln.Addr().(*net.TCPAddr)
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port))
}

func TestTCPExchange(t *testing.T) {
	t.Parallel()
	addr := startTCPEcho(t)

	ex, err := acidns.NewTCPExchanger(addr)
	require.NoError(t, err)

	q, err := wire.NewBuilder().
		ID(0xfeed).
		RecursionDesired(true).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	require.NoError(t, err)

	resp, err := ex.Exchange(t.Context(), q)
	require.NoError(t, err)
	require.Equal(t, q.ID(), resp.ID())
	require.Equal(t, 1, len(resp.Answers()))
	require.Equal(t, "203.0.113.5", resp.Answers()[0].RData().(rdata.A).Addr().String())
}

func TestTCPContextDeadline(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	a := ln.Addr().(*net.TCPAddr)

	ex, err := acidns.NewTCPExchanger(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port)))
	require.NoError(t, err)

	q, _ := wire.NewBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	_, err = ex.Exchange(ctx, q)
	require.Error(t, err)
}
