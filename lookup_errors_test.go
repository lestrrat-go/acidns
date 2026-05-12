package acidns_test

import (
	"context"
	"errors"
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

// startRCodeServer answers every query with the given RCODE and no
// records. Used to exercise the Lookup* error wrapping contract.
func startRCodeServer(t *testing.T, rcode wire.RCODE) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })

	go func() {
		buf := make([]byte, 4096)
		for {
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			req, err := wire.Unpack(buf[:n])
			if err != nil || len(req.Questions()) == 0 {
				continue
			}
			b := wire.NewMessageBuilder().
				ID(req.ID()).
				Response(true).
				RecursionAvailable(true).
				Question(req.Questions()[0])
			if rcode != wire.RCODENoError {
				b = b.RCODE(rcode)
			}
			resp, err := b.Build()
			if err != nil {
				continue
			}
			out, err := wire.Pack(resp)
			if err != nil {
				continue
			}
			_, _ = pc.WriteTo(out, src)
		}
	}()
	a := pc.LocalAddr().(*net.UDPAddr)
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port))
}

func TestLookupHostEmptyNoError(t *testing.T) {
	t.Parallel()
	// startTypedServer with no records of any type answers NoError + empty.
	addr := startRCodeServer(t, wire.RCODENoError)
	r := newResolverFor(t, addr)

	_, err := acidns.LookupHost(t.Context(), r, "example.com")
	require.Error(t, err)

	var dnsErr *net.DNSError
	require.True(t, errors.As(err, &dnsErr), "expected *net.DNSError, got %T: %v", err, err)
	require.True(t, dnsErr.IsNotFound, "empty NoError must surface as IsNotFound")
	require.False(t, dnsErr.IsTimeout)
	require.Equal(t, addr.String(), dnsErr.Server, "Server must carry the immediate upstream")
	require.Equal(t, "example.com", dnsErr.Name)
}

func TestLookupHostNXDOMAIN(t *testing.T) {
	t.Parallel()
	addr := startRCodeServer(t, wire.RCODENXDomain)
	r := newResolverFor(t, addr)

	_, err := acidns.LookupHost(t.Context(), r, "missing.example.com")
	require.Error(t, err)

	var dnsErr *net.DNSError
	require.True(t, errors.As(err, &dnsErr))
	require.True(t, dnsErr.IsNotFound)
	require.Equal(t, addr.String(), dnsErr.Server)

	// Backwards-compat: errors.Is must still reach *RCodeError.Is via
	// the DNSError.Unwrap chain.
	require.True(t, errors.Is(err, acidns.ErrNXDOMAIN),
		"errors.Is(err, ErrNXDOMAIN) must still match through the DNSError chain")
}

func TestLookupHostServFail(t *testing.T) {
	t.Parallel()
	addr := startRCodeServer(t, wire.RCODEServFail)
	r := newResolverFor(t, addr)

	_, err := acidns.LookupHost(t.Context(), r, "broken.example.com")
	require.Error(t, err)

	var dnsErr *net.DNSError
	require.True(t, errors.As(err, &dnsErr))
	require.False(t, dnsErr.IsNotFound)
	require.True(t, dnsErr.IsTemporary, "SERVFAIL maps to IsTemporary")
	require.Equal(t, addr.String(), dnsErr.Server)
	require.True(t, errors.Is(err, acidns.ErrServFail),
		"errors.Is(err, ErrServFail) must still match through the DNSError chain")
}

func TestLookupHostTimeout(t *testing.T) {
	t.Parallel()
	// Bind a UDP socket but never reply, so the context deadline fires
	// before any answer arrives.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	a := pc.LocalAddr().(*net.UDPAddr)
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(a.Port))
	r := newResolverFor(t, addr)

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	_, err = acidns.LookupHost(ctx, r, "slow.example.com")
	require.Error(t, err)

	var dnsErr *net.DNSError
	require.True(t, errors.As(err, &dnsErr), "expected *net.DNSError, got %T: %v", err, err)
	require.True(t, dnsErr.IsTimeout, "context deadline must surface as IsTimeout, got %+v", dnsErr)
	require.True(t, errors.Is(err, context.DeadlineExceeded),
		"errors.Is(err, context.DeadlineExceeded) must hold via DNSError.Unwrap")
}

func TestLookupANoRecords(t *testing.T) {
	t.Parallel()
	// Server has AAAA but no A — LookupA should report IsNotFound.
	addr := startRCodeServer(t, wire.RCODENoError)
	r := newResolverFor(t, addr)

	_, err := acidns.LookupA(t.Context(), r, wire.MustParseName("example.com."))
	require.Error(t, err)

	var dnsErr *net.DNSError
	require.True(t, errors.As(err, &dnsErr))
	require.True(t, dnsErr.IsNotFound)
	require.Equal(t, addr.String(), dnsErr.Server, "synthetic notFound must carry Answer.Server")
}

func TestLookupPTRInvalidAddr(t *testing.T) {
	t.Parallel()
	r := newResolverFor(t, netip.MustParseAddrPort("127.0.0.1:1"))

	_, err := acidns.LookupPTR(t.Context(), r, netip.Addr{})
	require.Error(t, err)

	var dnsErr *net.DNSError
	require.True(t, errors.As(err, &dnsErr), "invalid addr must surface as *net.DNSError")
	require.Equal(t, "invalid address", dnsErr.Err)
	require.False(t, dnsErr.IsNotFound, "invalid input is a programmer error, not NotFound")
}

// TestLookupHostUsesSpecificQtypeForUnsupportedRRType is a defensive
// check: empty NoError for the AAAA query alone (with valid A records)
// MUST NOT produce IsNotFound from LookupHost — there's data.
func TestLookupHostMixedFamilies(t *testing.T) {
	t.Parallel()
	name := wire.MustParseName("example.com.")
	addr := startTypedServer(t, map[rrtype.Type][]wire.Record{
		// A only; AAAA returns empty NoError. LookupHost should
		// still succeed with the IPv4 address.
		rrtype.A: {wire.NewRecord(name, time.Minute, mustA(t, "192.0.2.5"))},
	})
	r := newResolverFor(t, addr)

	addrs, err := acidns.LookupHost(t.Context(), r, "example.com")
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.5")}, addrs)
}

func mustA(t *testing.T, s string) rdata.RData {
	t.Helper()
	a, err := rdata.NewA(netip.MustParseAddr(s))
	require.NoError(t, err)
	return a
}
