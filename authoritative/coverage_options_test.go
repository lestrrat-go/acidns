package authoritative_test

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/authoritative"
	"github.com/lestrrat-go/acidns/update"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/zonefile"
	"github.com/stretchr/testify/require"
)

// TestWithMaxUpdateRecordsCapsInboundUpdate pins the secure-default
// behaviour: an inbound UPDATE carrying more (prereq + update) records
// than the configured cap is rejected with FormErr. The cap protects
// the authoritative server from a single authenticated UPDATE pinning
// arbitrary memory via the per-zone byName/namesExist map clone.
func TestWithMaxUpdateRecordsCapsInboundUpdate(t *testing.T) {
	t.Parallel()
	const zoneText = "$ORIGIN example.com.\n" +
		"$TTL 60\n" +
		"@ IN SOA ns hostmaster 1 60 60 60 60\n" +
		"@ IN NS ns\n" +
		"ns IN A 192.0.2.10\n"
	z, err := zonefile.Parse(strings.NewReader(zoneText))
	require.NoError(t, err)
	a, err := authoritative.New(
		authoritative.WithZone(z),
		authoritative.WithMaxUpdateRecords(2),
		authoritative.WithUpdatePolicy(func(_ context.Context, _ acidns.ResponseWriter, _ wire.Message) bool { return true }),
	)
	require.NoError(t, err)
	srv, err := acidns.NewUDPServer(netip.MustParseAddrPort("127.0.0.1:0"), a)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)
	require.NoError(t, err)

	// Build an UPDATE carrying 3 add-record entries — one past the cap.
	mkA := func(addr string) rdata.A {
		v, err := rdata.NewA(netip.MustParseAddr(addr))
		require.NoError(t, err)
		return v
	}
	mkRec := func(host, addr string) wire.Record {
		return wire.NewRecord(wire.MustParseName(host+".example.com"), 60*time.Second, mkA(addr))
	}
	msg, err := update.NewBuilder(wire.MustParseName("example.com")).
		AddRRset(mkRec("a", "198.51.100.1")).
		AddRRset(mkRec("b", "198.51.100.2")).
		AddRRset(mkRec("c", "198.51.100.3")).
		Build()
	require.NoError(t, err)

	ex, err := acidns.NewUDPClient(ctrl.Addr())
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), msg)
	require.NoError(t, err)
	require.Equal(t, wire.RCODEFormErr, resp.Flags().RCODE(),
		"UPDATE with > WithMaxUpdateRecords records must be rejected with FormErr")
}

// TestWithMaxUpdateRecordsAdmitsBelowCap is the negative control: an
// UPDATE within the cap must succeed (modulo the always-allow policy
// installed below).
func TestWithMaxUpdateRecordsAdmitsBelowCap(t *testing.T) {
	t.Parallel()
	const zoneText = "$ORIGIN example.com.\n" +
		"$TTL 60\n" +
		"@ IN SOA ns hostmaster 1 60 60 60 60\n" +
		"@ IN NS ns\n" +
		"ns IN A 192.0.2.10\n"
	z, err := zonefile.Parse(strings.NewReader(zoneText))
	require.NoError(t, err)
	a, err := authoritative.New(
		authoritative.WithZone(z),
		authoritative.WithMaxUpdateRecords(10),
		authoritative.WithUpdatePolicy(func(_ context.Context, _ acidns.ResponseWriter, _ wire.Message) bool { return true }),
	)
	require.NoError(t, err)
	srv, err := acidns.NewUDPServer(netip.MustParseAddrPort("127.0.0.1:0"), a)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)
	require.NoError(t, err)

	ar, err := rdata.NewA(netip.MustParseAddr("198.51.100.5"))
	require.NoError(t, err)
	msg, err := update.NewBuilder(wire.MustParseName("example.com")).
		AddRRset(wire.NewRecord(wire.MustParseName("blog.example.com"), 60*time.Second, ar)).
		Build()
	require.NoError(t, err)
	ex, err := acidns.NewUDPClient(ctrl.Addr())
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), msg)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())
}

// TestWithMaxNotifyInflightAccepted documents the construction-only
// posture for the NOTIFY-handler concurrency cap. Driving the cap
// requires a slow NotifyHandler installed via WithNotifyHandler plus
// concurrent NOTIFY senders that observe back-pressure or drops; the
// machinery exists in notify_test.go, but per-option saturation isn't
// the right behavioural test scope here.
func TestWithMaxNotifyInflightAccepted(t *testing.T) {
	t.Parallel()
	const zoneText = "$ORIGIN example.com.\n" +
		"$TTL 60\n" +
		"@ IN SOA ns hostmaster 1 60 60 60 60\n" +
		"@ IN NS ns\n" +
		"ns IN A 192.0.2.10\n"
	z, err := zonefile.Parse(strings.NewReader(zoneText))
	require.NoError(t, err)
	h, err := authoritative.New(
		authoritative.WithZone(z),
		authoritative.WithMaxNotifyInflight(8),
	)
	require.NoError(t, err)
	require.NotNil(t, h)
}
