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

const updateZone = `$ORIGIN example.com.
$TTL 60
@   IN  SOA  ns1.example.com. hm.example.com. ( 1 2 3 4 5 )
@   IN  NS   ns1.example.com.
ns1 IN  A    192.0.2.10
www IN  A    192.0.2.42
`

func startUpdatable(t *testing.T) (*authoritative.Authoritative, netip.AddrPort) {
	t.Helper()
	z, err := zonefile.Parse(strings.NewReader(updateZone))
	require.NoError(t, err)
	a, err := authoritative.New(
		authoritative.WithZone(z),
		authoritative.WithUpdatePolicy(func(_ context.Context, _ acidns.ResponseWriter, _ wire.Message) bool { return true }),
	)
	require.NoError(t, err)
	srv, err := acidns.NewUDPServer(netip.MustParseAddrPort("127.0.0.1:0"), a)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)

	require.NoError(t, err)
	return a, ctrl.Addr()
}

func TestUpdateAddRRset(t *testing.T) {
	t.Parallel()
	a, addr := startUpdatable(t)

	// Add new record at "blog.example.com".
	ar, err := rdata.NewA(netip.MustParseAddr("198.51.100.5"))
	require.NoError(t, err)
	added := wire.NewRecord(wire.MustParseName("blog.example.com"), 60*time.Second,
		ar)

	ex, err := acidns.NewUDPClient(addr)
	require.NoError(t, err)
	msg, err := update.NewBuilder(wire.MustParseName("example.com")).
		AddRRset(added).
		Build()
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), msg)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())

	// Verify the new record appears in subsequent queries.
	q, _ := wire.NewMessageBuilder().
		ID(2).
		Question(wire.NewQuestion(wire.MustParseName("blog.example.com"), rrtype.A)).
		Build()
	r2, err := ex.Exchange(t.Context(), q)
	require.NoError(t, err)
	require.Equal(t, 1, len(r2.Answers()))
	require.Equal(t, "198.51.100.5", r2.Answers()[0].RData().(rdata.A).Addr().String())
	_ = a
}

func TestUpdateDeleteRRset(t *testing.T) {
	t.Parallel()
	_, addr := startUpdatable(t)

	ex, err := acidns.NewUDPClient(addr)
	require.NoError(t, err)
	msg, err := update.NewBuilder(wire.MustParseName("example.com")).
		DeleteRRset(wire.MustParseName("www.example.com"), rrtype.A).
		Build()
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), msg)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())

	// Now www.example.com should NXDOMAIN (we don't keep namesExist after delete) or NODATA.
	q, _ := wire.NewMessageBuilder().
		ID(3).
		Question(wire.NewQuestion(wire.MustParseName("www.example.com"), rrtype.A)).
		Build()
	r, err := ex.Exchange(t.Context(), q)
	require.NoError(t, err)
	require.Equal(t, 0, len(r.Answers()))
}

func TestUpdatePrereqRRsetExistsFails(t *testing.T) {
	t.Parallel()
	_, addr := startUpdatable(t)

	ex, err := acidns.NewUDPClient(addr)
	require.NoError(t, err)
	ar2, err := rdata.NewA(netip.MustParseAddr("198.51.100.7"))
	require.NoError(t, err)
	msg, err := update.NewBuilder(wire.MustParseName("example.com")).
		PrereqRRsetExists(wire.MustParseName("nope.example.com"), rrtype.A).
		AddRRset(wire.NewRecord(wire.MustParseName("blog.example.com"), 60*time.Second,
			ar2)).
		Build()
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), msg)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENXRRSet, resp.Flags().RCODE())
}

func TestUpdatePrereqRRsetAbsentSucceeds(t *testing.T) {
	t.Parallel()
	_, addr := startUpdatable(t)

	ex, err := acidns.NewUDPClient(addr)
	require.NoError(t, err)
	ar3, err := rdata.NewA(netip.MustParseAddr("198.51.100.8"))
	require.NoError(t, err)
	msg, err := update.NewBuilder(wire.MustParseName("example.com")).
		PrereqRRsetAbsent(wire.MustParseName("blog.example.com"), rrtype.A).
		AddRRset(wire.NewRecord(wire.MustParseName("blog.example.com"), 60*time.Second,
			ar3)).
		Build()
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), msg)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())
}

// TestUpdateConcurrentWithQuery exercises the UPDATE-vs-query race that
// existed when serveUpdate mutated zoneIndex maps in place while answer
// (called outside a.mu) read them. Without copy-on-write the Go runtime
// faults with "concurrent map read and write"; with the fix in place
// the test is purely a smoke-test that updates and queries interleave.
func TestUpdateConcurrentWithQuery(t *testing.T) {
	t.Parallel()
	_, addr := startUpdatable(t)

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	const writers = 4
	const readers = 8

	var updateOps atomic.Int64
	var queryOps atomic.Int64
	var wg sync.WaitGroup

	for i := range writers {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ex, err := acidns.NewUDPClient(addr)
			if err != nil {
				return
			}
			ip := netip.AddrFrom4([4]byte{198, 51, 100, byte(10 + id)})
			ar4, err := rdata.NewA(ip)
			require.NoError(t, err)
			rec := wire.NewRecord(wire.MustParseName("blog.example.com"), 60*time.Second, ar4)
			for ctx.Err() == nil {
				msg, err := update.NewBuilder(wire.MustParseName("example.com")).AddRRset(rec).Build()
				if err != nil {
					return
				}
				if _, err := ex.Exchange(ctx, msg); err != nil {
					return
				}
				updateOps.Add(1)
			}
		}(i)
	}

	for range readers {
		wg.Go(func() {
			ex, err := acidns.NewUDPClient(addr)
			if err != nil {
				return
			}
			q, _ := wire.NewMessageBuilder().
				ID(1).
				Question(wire.NewQuestion(wire.MustParseName("blog.example.com"), rrtype.A)).
				Build()
			for ctx.Err() == nil {
				if _, err := ex.Exchange(ctx, q); err != nil {
					return
				}
				queryOps.Add(1)
			}
		})
	}

	wg.Wait()
	require.NotZero(t, updateOps.Load(), "no updates ran")
	require.NotZero(t, queryOps.Load(), "no queries ran")
}

func TestUpdateOutOfZoneRefused(t *testing.T) {
	t.Parallel()
	_, addr := startUpdatable(t)
	ex, err := acidns.NewUDPClient(addr)
	require.NoError(t, err)
	ar5, err := rdata.NewA(netip.MustParseAddr("198.51.100.9"))
	require.NoError(t, err)
	msg, err := update.NewBuilder(wire.MustParseName("example.org")).
		AddRRset(wire.NewRecord(wire.MustParseName("a.example.org"), 60*time.Second,
			ar5)).
		Build()
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), msg)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENotAuth, resp.Flags().RCODE())
}
