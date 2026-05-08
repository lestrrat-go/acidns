package authoritative_test

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/authoritative"
	"github.com/lestrrat-go/acidns/update"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/zonefile"
	"github.com/stretchr/testify/require"
)

func TestUpdateRefusedByDefault(t *testing.T) {
	t.Parallel()

	z, err := zonefile.Parse(strings.NewReader(updateZone))
	require.NoError(t, err)
	a, err := authoritative.New(authoritative.WithZone(z)) // no policy installed
	require.NoError(t, err)

	srv, err := acidns.ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"), a)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx) }()

	ex, err := acidns.NewUDPExchanger(srv.Addr())
	require.NoError(t, err)
	msg, err := update.NewBuilder(wire.MustParseName("example.com")).
		AddRRset(wire.NewRecord(wire.MustParseName("blog.example.com"),
			60*time.Second, rdata.NewA(netip.MustParseAddr("198.51.100.1")))).
		Build()
	require.NoError(t, err)

	resp, err := ex.Exchange(ctx, msg)
	require.NoError(t, err)
	require.Equal(t, wire.RCODERefused, resp.Flags().RCODE(),
		"unauthenticated UPDATE must be REFUSED when no policy is configured")

	// And the zone state must be unchanged.
	q, err := wire.NewBuilder().
		ID(0xfeed).
		Question(wire.NewQuestion(wire.MustParseName("blog.example.com"), rrtype.A)).
		Build()
	require.NoError(t, err)
	resp, err = ex.Exchange(ctx, q)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENXDomain, resp.Flags().RCODE(),
		"the unauthenticated UPDATE must NOT have inserted the record")
}

// TestUpdatePolicyReceivesRawRequest confirms that an UpdatePolicy can
// recover the original wire bytes via [acidns.RawRequest], which is the
// only way to perform RFC 3007 TSIG verification (re-marshalling q
// isn't byte-stable).
func TestUpdatePolicyReceivesRawRequest(t *testing.T) {
	t.Parallel()

	z, err := zonefile.Parse(strings.NewReader(updateZone))
	require.NoError(t, err)

	var (
		rawMu   sync.Mutex
		rawSeen []byte
	)
	a, err := authoritative.New(
		authoritative.WithZone(z),
		authoritative.WithUpdatePolicy(func(ctx context.Context, _ acidns.ResponseWriter, _ wire.Message) bool {
			b, ok := acidns.RawRequest(ctx)
			if ok {
				rawMu.Lock()
				rawSeen = append([]byte(nil), b...)
				rawMu.Unlock()
			}
			return true
		}),
	)
	require.NoError(t, err)

	srv, err := acidns.ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"), a)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx) }()

	ex, err := acidns.NewUDPExchanger(srv.Addr())
	require.NoError(t, err)
	msg, err := update.NewBuilder(wire.MustParseName("example.com")).
		AddRRset(wire.NewRecord(wire.MustParseName("blog.example.com"),
			60*time.Second, rdata.NewA(netip.MustParseAddr("198.51.100.5")))).
		Build()
	require.NoError(t, err)

	expectedBytes, err := wire.Marshal(msg)
	require.NoError(t, err)

	_, err = ex.Exchange(ctx, msg)
	require.NoError(t, err)

	rawMu.Lock()
	defer rawMu.Unlock()
	require.NotEmpty(t, rawSeen, "policy must observe raw request bytes via RawRequest()")
	require.Equal(t, expectedBytes, rawSeen,
		"raw bytes received by the policy must equal the wire bytes the client sent")
}

func TestUpdatePolicyAllowsExplicitOptIn(t *testing.T) {
	t.Parallel()

	z, err := zonefile.Parse(strings.NewReader(updateZone))
	require.NoError(t, err)

	var called atomic.Bool
	a, err := authoritative.New(
		authoritative.WithZone(z),
		authoritative.WithUpdatePolicy(func(_ context.Context, _ acidns.ResponseWriter, _ wire.Message) bool {
			called.Store(true)
			return true
		}),
	)
	require.NoError(t, err)

	srv, err := acidns.ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"), a)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx) }()

	ex, err := acidns.NewUDPExchanger(srv.Addr())
	require.NoError(t, err)
	msg, err := update.NewBuilder(wire.MustParseName("example.com")).
		AddRRset(wire.NewRecord(wire.MustParseName("blog.example.com"),
			60*time.Second, rdata.NewA(netip.MustParseAddr("198.51.100.5")))).
		Build()
	require.NoError(t, err)
	resp, err := ex.Exchange(ctx, msg)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE(),
		"policy returning true must admit the UPDATE")
	require.True(t, called.Load(), "policy must be invoked")
}
