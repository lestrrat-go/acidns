package authoritative_test

import (
	"context"
	"net/netip"
	"strings"
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

// TestUpdateApexCNAMERejected verifies that AddZone refuses a zone
// whose apex carries a CNAME or DNAME. RFC 1034 §3.6.2 forbids it.
func TestUpdateApexCNAMERejected(t *testing.T) {
	t.Parallel()
	zoneText := `$ORIGIN example.com.
$TTL 60
@   IN  SOA  ns1.example.com. hm.example.com. ( 1 2 3 4 5 )
@   IN  NS   ns1.example.com.
@   IN  CNAME other.example.com.
ns1 IN  A    192.0.2.10
`
	z, err := zonefile.Parse(strings.NewReader(zoneText))
	require.NoError(t, err)
	_, err = authoritative.New(authoritative.WithZone(z))
	require.ErrorIs(t, err, authoritative.ErrApexCNAMEOrDNAME)
}

// TestUpdateRecordOutOfZoneNotZone verifies that an UPDATE containing a
// record name outside the targeted zone is rejected with NotZone.
// RFC 2136 §3.4.2.4.
func TestUpdateRecordOutOfZoneNotZone(t *testing.T) {
	t.Parallel()
	_, addr := startUpdatable(t)

	ex, err := acidns.NewUDPExchanger(addr)
	require.NoError(t, err)

	// Targets example.com (we own it) but plants `evil.com` inside.
	msg, err := update.NewUpdateBuilder(wire.MustParseName("example.com")).
		AddRRset(wire.NewRecord(wire.MustParseName("evil.com"), 60*time.Second,
			rdata.MustNewA(netip.MustParseAddr("198.51.100.99")))).
		Build()
	require.NoError(t, err)

	resp, err := ex.Exchange(t.Context(), msg)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENotZone, resp.Flags().RCODE())
}

// TestUpdateApexCNAMEAddRejected verifies that a successful UPDATE
// cannot plant a CNAME at the apex of a zone (which would violate
// RFC 1034 §3.6.2 the same way an apex CNAME at load time would).
func TestUpdateApexCNAMEAddRejected(t *testing.T) {
	t.Parallel()
	_, addr := startUpdatable(t)

	ex, err := acidns.NewUDPExchanger(addr)
	require.NoError(t, err)

	msg, err := update.NewUpdateBuilder(wire.MustParseName("example.com")).
		AddRRset(wire.NewRecord(wire.MustParseName("example.com"), 60*time.Second,
			rdata.MustNewCNAME(wire.MustParseName("other.example.com")))).
		Build()
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), msg)
	require.NoError(t, err)
	require.Equal(t, wire.RCODEFormErr, resp.Flags().RCODE())
}

// TestUpdateValueDependentPrereqMatch covers the §2.4.2 path: an
// UPDATE may carry an IN-class prereq specifying that an RRset has
// exactly the listed values; the update proceeds only if it does.
func TestUpdateValueDependentPrereqMatch(t *testing.T) {
	t.Parallel()
	_, addr := startUpdatable(t)
	ex, err := acidns.NewUDPExchanger(addr)
	require.NoError(t, err)

	// www.example.com IN A 192.0.2.42 — see the fixture.
	prereq := wire.NewRecord(wire.MustParseName("www.example.com"), 0,
		rdata.MustNewA(netip.MustParseAddr("192.0.2.42")))
	msg, err := wire.NewMessageBuilder().
		ID(0x1111).
		Opcode(wire.OpcodeUpdate).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.SOA)).
		Answer(prereq).
		Authority(wire.NewRecord(wire.MustParseName("blog.example.com"), 60*time.Second,
			rdata.MustNewA(netip.MustParseAddr("198.51.100.7")))).
		Build()
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), msg)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())
}

// TestUpdateValueDependentPrereqMismatch: the prereq RRset doesn't
// match the zone's RRset → NXRRSet.
func TestUpdateValueDependentPrereqMismatch(t *testing.T) {
	t.Parallel()
	_, addr := startUpdatable(t)
	ex, err := acidns.NewUDPExchanger(addr)
	require.NoError(t, err)

	// www.example.com IN A 192.0.2.42 in the zone; we claim 192.0.2.99.
	prereq := wire.NewRecord(wire.MustParseName("www.example.com"), 0,
		rdata.MustNewA(netip.MustParseAddr("192.0.2.99")))
	msg, err := wire.NewMessageBuilder().
		ID(0x2222).
		Opcode(wire.OpcodeUpdate).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.SOA)).
		Answer(prereq).
		Authority(wire.NewRecord(wire.MustParseName("blog.example.com"), 60*time.Second,
			rdata.MustNewA(netip.MustParseAddr("198.51.100.7")))).
		Build()
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), msg)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENXRRSet, resp.Flags().RCODE())
}

// TestUpdateBumpsSOAOnChange verifies RFC 2136 §3.7: the SOA serial
// increments after any change-effecting UPDATE, and the OnUpdate hook
// receives the (old, new) pair.
func TestUpdateBumpsSOAOnChange(t *testing.T) {
	t.Parallel()
	z, err := zonefile.Parse(strings.NewReader(updateZone))
	require.NoError(t, err)
	var calls atomic.Int32
	var sawOld, sawNew atomic.Uint32
	a, err := authoritative.New(
		authoritative.WithZone(z),
		authoritative.WithUpdatePolicy(func(_ context.Context, _ acidns.ResponseWriter, _ wire.Message) bool { return true }),
		authoritative.WithOnUpdate(func(_ context.Context, _ wire.Name, oldS, newS uint32) {
			calls.Add(1)
			sawOld.Store(oldS)
			sawNew.Store(newS)
		}),
	)
	require.NoError(t, err)
	srv, err := acidns.NewUDPServer(netip.MustParseAddrPort("127.0.0.1:0"), a)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)
	require.NoError(t, err)
	addr := ctrl.Addr()

	ex, err := acidns.NewUDPExchanger(addr)
	require.NoError(t, err)

	added := wire.NewRecord(wire.MustParseName("blog.example.com"), 60*time.Second,
		rdata.MustNewA(netip.MustParseAddr("198.51.100.5")))
	msg, err := update.NewUpdateBuilder(wire.MustParseName("example.com")).
		AddRRset(added).
		Build()
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), msg)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())

	// Read the apex SOA to confirm the bump.
	q, err := wire.NewMessageBuilder().
		ID(0x3333).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.SOA)).
		Build()
	require.NoError(t, err)
	soaResp, err := ex.Exchange(t.Context(), q)
	require.NoError(t, err)
	require.NotEmpty(t, soaResp.Answers())
	soa, ok := wire.RDataAs[rdata.SOA](soaResp.Answers()[0])
	require.True(t, ok)
	require.Equal(t, uint32(2), soa.Serial(), "SOA serial must increment from 1 to 2")
	require.Equal(t, int32(1), calls.Load())
	require.Equal(t, uint32(1), sawOld.Load())
	require.Equal(t, uint32(2), sawNew.Load())

	// Idempotent re-add: SOA must NOT bump again, OnUpdate must NOT fire.
	resp, err = ex.Exchange(t.Context(), msg)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())
	require.Equal(t, int32(1), calls.Load(), "idempotent add must not fire OnUpdate")
}
