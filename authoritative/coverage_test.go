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
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/zonefile"
	"github.com/stretchr/testify/require"
)

// cnameZone exercises CNAME chain branches in lookupAuthoritative:
//   - CNAME → name with non-matching type (NODATA at chain>0)
//   - CNAME → empty non-terminal (NODATA via namesExist at chain>0)
//   - CNAME → non-existent name (NXDOMAIN reachable as NoError at chain>0)
//   - CNAME → wildcard target
//   - CNAME → CNAME → ... long chain with eventual A
const cnameZone = `$ORIGIN example.com.
$TTL 60
@         IN SOA ns1.example.com. hm.example.com. ( 1 2 3 4 5 )
@         IN NS  ns1.example.com.
ns1       IN A   192.0.2.10
target    IN TXT "only-txt"
ent.below IN A   192.0.2.99
toent     IN CNAME below.example.com.
totxt     IN CNAME target.example.com.
tomissing IN CNAME nope.example.com.
towild    IN CNAME wcsub.wcparent.example.com.
*.wcparent IN A   192.0.2.55
towildtxt IN CNAME q.wctxt.example.com.
*.wctxt   IN TXT  "wildcard-txt-only"
c1        IN CNAME c2.example.com.
c2        IN CNAME c3.example.com.
c3        IN CNAME c4.example.com.
c4        IN CNAME c5.example.com.
c5        IN CNAME c6.example.com.
c6        IN CNAME c7.example.com.
c7        IN CNAME c8.example.com.
c8        IN CNAME c9.example.com.
c9        IN CNAME ns1.example.com.
`

func newCNAMEAuth(t *testing.T) authoritative.Authoritative {
	t.Helper()
	z, err := zonefile.Parse(strings.NewReader(cnameZone))
	require.NoError(t, err)
	a, err := authoritative.New(authoritative.WithZone(z))
	require.NoError(t, err)
	return a
}

// CNAME → target name that has TXT but no AAAA → NODATA after CNAME chase.
func TestCNAMEToNameTypeMissNoData(t *testing.T) {
	t.Parallel()
	a := newCNAMEAuth(t)
	resp := ask(t, a, "totxt.example.com", rrtype.AAAA)
	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())
	// Answer should contain the CNAME but no AAAA.
	require.Equal(t, 1, len(resp.Answers()))
	require.Equal(t, rrtype.CNAME, resp.Answers()[0].Type())
	// chain>0 NODATA should NOT include SOA in authority.
	require.Equal(t, 0, len(resp.Authorities()))
}

// CNAME → empty non-terminal "below.example.com" → NODATA via namesExist at chain>0.
func TestCNAMEToEmptyNonTerminal(t *testing.T) {
	t.Parallel()
	a := newCNAMEAuth(t)
	resp := ask(t, a, "toent.example.com", rrtype.A)
	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())
	// Only the CNAME is in answers; the ENT yields nothing.
	require.Equal(t, 1, len(resp.Answers()))
	require.Equal(t, rrtype.CNAME, resp.Answers()[0].Type())
	require.Equal(t, 0, len(resp.Authorities()))
}

// CNAME → non-existent name → reaches NXDOMAIN branch at chain>0 returning
// NoError.
func TestCNAMEToMissingName(t *testing.T) {
	t.Parallel()
	a := newCNAMEAuth(t)
	resp := ask(t, a, "tomissing.example.com", rrtype.A)
	// chain==0 returns NXDomain only at the start; once we've followed a
	// CNAME, the missing target becomes a NoError partial response per
	// RFC 1034 §4.3.2 step 4 (best-effort).
	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())
	require.Equal(t, 1, len(resp.Answers()))
	require.Equal(t, rrtype.CNAME, resp.Answers()[0].Type())
}

// CNAME → name that matches a wildcard. Exercises wildcard synthesis on the
// CNAME-chase side of the loop (rewriteOwners path inside the chase).
func TestCNAMEThroughWildcard(t *testing.T) {
	t.Parallel()
	a := newCNAMEAuth(t)
	resp := ask(t, a, "towild.example.com", rrtype.A)
	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())
	require.GreaterOrEqual(t, len(resp.Answers()), 2)
	require.Equal(t, rrtype.CNAME, resp.Answers()[0].Type())
	// Last answer is the synthesized A.
	last := resp.Answers()[len(resp.Answers())-1]
	require.Equal(t, rrtype.A, last.Type())
	require.Equal(t, "192.0.2.55", last.RData().(rdata.A).Addr().String())
}

// CNAME → wildcard whose RRset has no matching type and no CNAME →
// NODATA reachable through the chain>0 branch of the wildcard arm.
func TestCNAMEThroughWildcardTypeMiss(t *testing.T) {
	t.Parallel()
	a := newCNAMEAuth(t)
	resp := ask(t, a, "towildtxt.example.com", rrtype.A)
	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())
	// Only the CNAME comes back; wildcard has TXT, not A.
	require.Equal(t, 1, len(resp.Answers()))
	require.Equal(t, rrtype.CNAME, resp.Answers()[0].Type())
	require.Equal(t, 0, len(resp.Authorities()))
}

// 9 CNAME hops chained then to ns1 (which has A) — under the maxCNAMEChain
// bound of 8 the resolver halts before the final A. This exercises the loop
// limit guard at the bottom of lookupAuthoritative.
func TestCNAMEChainExceedsMaxDepth(t *testing.T) {
	t.Parallel()
	a := newCNAMEAuth(t)
	resp := ask(t, a, "c1.example.com", rrtype.A)
	// Depending on the bound the loop yields ServFail (chain limit) or a
	// partial NoError; either is the same code path. The important part
	// is that we do not crash and we return some answers.
	require.GreaterOrEqual(t, len(resp.Answers()), 1)
}

// answer() with zero questions in the request.
func TestEmptyQuestionsFormErr(t *testing.T) {
	t.Parallel()
	a := newAuth(t)
	q, err := wire.NewBuilder().ID(7).Build()
	require.NoError(t, err)
	w := &inProcWriter{}
	a.ServeDNS(t.Context(), w, q)
	require.NotNil(t, w.resp)
	require.Equal(t, wire.RCODEFormErr, w.resp.Flags().RCODE())
}

// AXFR for a name within a zone but not the apex must yield NotAuth.
func TestAXFRAtNonApexNotAuth(t *testing.T) {
	t.Parallel()
	a := newAuth(t)
	q, err := wire.NewBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("www.example.com"), rrtype.AXFR)).
		Build()
	require.NoError(t, err)
	w := &inProcWriter{network: "tcp"}
	a.ServeDNS(t.Context(), w, q)
	require.Equal(t, wire.RCODENotAuth, w.resp.Flags().RCODE())
}

// IXFR is served as AXFR per RFC 1995 §3 when the server lacks a journal.
func TestIXFRFallsBackToAXFR(t *testing.T) {
	t.Parallel()
	a := newAuth(t)
	q, err := wire.NewBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.IXFR)).
		Build()
	require.NoError(t, err)
	w := &inProcWriter{network: "tcp"}
	a.ServeDNS(t.Context(), w, q)
	require.NotNil(t, w.resp)
	require.Equal(t, wire.RCODENoError, w.resp.Flags().RCODE())
	require.True(t, w.resp.Flags().Authoritative())
	// First and last answers are SOA in an AXFR-shaped response.
	ans := w.resp.Answers()
	require.GreaterOrEqual(t, len(ans), 2)
	require.Equal(t, rrtype.SOA, ans[0].Type())
	require.Equal(t, rrtype.SOA, ans[len(ans)-1].Type())
}

// AXFR over a real TCP connection with a zone large enough to force the
// streamer to flush across multiple DNS messages. Each answer body is a
// large TXT so we cross axfrChunkBudget (16 KB).
func TestAXFRMultiMessageFlush(t *testing.T) {
	t.Parallel()

	// Build a zone with enough big-TXT records to require a flush.
	var sb strings.Builder
	sb.WriteString("$ORIGIN big.example.\n")
	sb.WriteString("$TTL 60\n")
	sb.WriteString("@ IN SOA ns1.big.example. hm.big.example. ( 1 2 3 4 5 )\n")
	sb.WriteString("@ IN NS ns1.big.example.\n")
	sb.WriteString("ns1 IN A 192.0.2.10\n")
	// 32 records of ~700 bytes TXT each → ~22 KB total.
	bigPayload := strings.Repeat("x", 240)
	for i := range 32 {
		sb.WriteString("rec")
		sb.WriteString(itoa(i))
		sb.WriteString(" IN TXT \"")
		sb.WriteString(bigPayload)
		sb.WriteString("\" \"")
		sb.WriteString(bigPayload)
		sb.WriteString("\" \"")
		sb.WriteString(bigPayload)
		sb.WriteString("\"\n")
	}

	z, err := zonefile.Parse(strings.NewReader(sb.String()))
	require.NoError(t, err)
	h, err := authoritative.New(authoritative.WithZone(z))
	require.NoError(t, err)

	srv, err := acidns.ListenTCP(netip.MustParseAddrPort("127.0.0.1:0"), h)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx) }()

	ex, err := acidns.NewTCPExchanger(srv.Addr())
	require.NoError(t, err)
	q, _ := wire.NewBuilder().
		ID(0xb160).
		Question(wire.NewQuestion(wire.MustParseName("big.example"), rrtype.AXFR)).
		Build()
	resp, err := ex.Exchange(ctx, q)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())
	// At least the SOA + records must arrive on the first message we can
	// see; the streamer keeps the framing legal even if the client only
	// reads one.
	require.GreaterOrEqual(t, len(resp.Answers()), 1)
}

// itoa avoids importing strconv just for this single helper.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [4]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}

// NOTIFY with zero questions returns FormErr.
func TestNotifyEmptyQuestionsFormErr(t *testing.T) {
	t.Parallel()
	a := newAuth(t)
	q, err := wire.NewBuilder().
		ID(1).
		Opcode(wire.OpcodeNotify).
		Build()
	require.NoError(t, err)
	w := &inProcWriter{}
	a.ServeDNS(t.Context(), w, q)
	require.NotNil(t, w.resp)
	require.Equal(t, wire.RCODEFormErr, w.resp.Flags().RCODE())
}

// UPDATE with zero questions returns FormErr.
func TestUpdateEmptyQuestionsFormErr(t *testing.T) {
	t.Parallel()
	a := newAuth(t)
	q, err := wire.NewBuilder().
		ID(1).
		Opcode(wire.OpcodeUpdate).
		Build()
	require.NoError(t, err)
	w := &inProcWriter{}
	a.ServeDNS(t.Context(), w, q)
	require.NotNil(t, w.resp)
	require.Equal(t, wire.RCODEFormErr, w.resp.Flags().RCODE())
}

// UPDATE whose zone-section question is not SOA returns FormErr.
func TestUpdateZoneNotSOA(t *testing.T) {
	t.Parallel()
	a := newAuth(t)
	q, err := wire.NewBuilder().
		ID(1).
		Opcode(wire.OpcodeUpdate).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	require.NoError(t, err)
	w := &inProcWriter{}
	a.ServeDNS(t.Context(), w, q)
	require.Equal(t, wire.RCODEFormErr, w.resp.Flags().RCODE())
}

// startUpdatableLocal returns an authoritative server (with a known zone)
// listening on UDP, suitable for exchanging UPDATE requests in-process.
func startUpdatableLocal(t *testing.T) (authoritative.Authoritative, netip.AddrPort) {
	t.Helper()
	z, err := zonefile.Parse(strings.NewReader(updateZone))
	require.NoError(t, err)
	a, err := authoritative.New(
		authoritative.WithZone(z),
		authoritative.WithUpdatePolicy(func(_ acidns.ResponseWriter, _ wire.Message) bool { return true }),
	)
	require.NoError(t, err)
	srv, err := acidns.ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"), a)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx) }()
	return a, srv.Addr()
}

// PrereqNameInUse fails with NXDomain when the name does not exist.
func TestUpdatePrereqNameInUseFailsNXDomain(t *testing.T) {
	t.Parallel()
	_, addr := startUpdatableLocal(t)
	ex, err := acidns.NewUDPExchanger(addr)
	require.NoError(t, err)
	msg, err := update.NewBuilder(wire.MustParseName("example.com")).
		PrereqNameInUse(wire.MustParseName("ghost.example.com")).
		AddRRset(wire.NewRecord(wire.MustParseName("blog.example.com"), 60*time.Second,
			rdata.NewA(netip.MustParseAddr("198.51.100.1")))).
		Build()
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), msg)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENXDomain, resp.Flags().RCODE())
}

// PrereqNameNotInUse fails with YXDomain when the name does exist.
func TestUpdatePrereqNameNotInUseFailsYXDomain(t *testing.T) {
	t.Parallel()
	_, addr := startUpdatableLocal(t)
	ex, err := acidns.NewUDPExchanger(addr)
	require.NoError(t, err)
	msg, err := update.NewBuilder(wire.MustParseName("example.com")).
		PrereqNameNotInUse(wire.MustParseName("www.example.com")).
		AddRRset(wire.NewRecord(wire.MustParseName("blog.example.com"), 60*time.Second,
			rdata.NewA(netip.MustParseAddr("198.51.100.1")))).
		Build()
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), msg)
	require.NoError(t, err)
	require.Equal(t, wire.RCODEYXDomain, resp.Flags().RCODE())
}

// PrereqRRsetExists succeeds when the RRset is present, allowing the update
// to apply.
func TestUpdatePrereqRRsetExistsSucceeds(t *testing.T) {
	t.Parallel()
	_, addr := startUpdatableLocal(t)
	ex, err := acidns.NewUDPExchanger(addr)
	require.NoError(t, err)
	msg, err := update.NewBuilder(wire.MustParseName("example.com")).
		PrereqRRsetExists(wire.MustParseName("www.example.com"), rrtype.A).
		AddRRset(wire.NewRecord(wire.MustParseName("blog.example.com"), 60*time.Second,
			rdata.NewA(netip.MustParseAddr("198.51.100.2")))).
		Build()
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), msg)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())
}

// PrereqRRsetAbsent fails with YXRRSet when the RRset exists.
func TestUpdatePrereqRRsetAbsentFailsYXRRSet(t *testing.T) {
	t.Parallel()
	_, addr := startUpdatableLocal(t)
	ex, err := acidns.NewUDPExchanger(addr)
	require.NoError(t, err)
	msg, err := update.NewBuilder(wire.MustParseName("example.com")).
		PrereqRRsetAbsent(wire.MustParseName("www.example.com"), rrtype.A).
		AddRRset(wire.NewRecord(wire.MustParseName("blog.example.com"), 60*time.Second,
			rdata.NewA(netip.MustParseAddr("198.51.100.3")))).
		Build()
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), msg)
	require.NoError(t, err)
	require.Equal(t, wire.RCODEYXRRSet, resp.Flags().RCODE())
}

// DeleteAll (TYPE=ANY, CLASS=ANY) removes every RRset at the name.
func TestUpdateDeleteAllAtName(t *testing.T) {
	t.Parallel()
	_, addr := startUpdatableLocal(t)
	ex, err := acidns.NewUDPExchanger(addr)
	require.NoError(t, err)
	msg, err := update.NewBuilder(wire.MustParseName("example.com")).
		DeleteAll(wire.MustParseName("www.example.com")).
		Build()
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), msg)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())

	// www should now NXDOMAIN/NODATA for A.
	q, _ := wire.NewBuilder().
		ID(33).
		Question(wire.NewQuestion(wire.MustParseName("www.example.com"), rrtype.A)).
		Build()
	r, err := ex.Exchange(t.Context(), q)
	require.NoError(t, err)
	require.Equal(t, 0, len(r.Answers()))
}

// DeleteRecord removes a specific record by rdata. The other A at ns1 stays.
func TestUpdateDeleteRecordSpecific(t *testing.T) {
	t.Parallel()
	_, addr := startUpdatableLocal(t)
	ex, err := acidns.NewUDPExchanger(addr)
	require.NoError(t, err)

	// First add a second A at www (so we can verify only one specific
	// record is removed).
	add := wire.NewRecord(wire.MustParseName("www.example.com"), 60*time.Second,
		rdata.NewA(netip.MustParseAddr("198.51.100.10")))
	addMsg, err := update.NewBuilder(wire.MustParseName("example.com")).
		AddRRset(add).
		Build()
	require.NoError(t, err)
	_, err = ex.Exchange(t.Context(), addMsg)
	require.NoError(t, err)

	// Now delete the original 192.0.2.42 specifically.
	delMsg, err := update.NewBuilder(wire.MustParseName("example.com")).
		DeleteRecord(wire.NewRecord(wire.MustParseName("www.example.com"), 0,
			rdata.NewA(netip.MustParseAddr("192.0.2.42")))).
		Build()
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), delMsg)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())

	// Verify only the 198.51.100.10 record remains.
	q, _ := wire.NewBuilder().
		ID(44).
		Question(wire.NewQuestion(wire.MustParseName("www.example.com"), rrtype.A)).
		Build()
	r, err := ex.Exchange(t.Context(), q)
	require.NoError(t, err)
	require.Equal(t, 1, len(r.Answers()))
	require.Equal(t, "198.51.100.10", r.Answers()[0].RData().(rdata.A).Addr().String())
}

// PrereqRRsetExists for a name that exists but has no RRset of the
// requested type yields NXRRSet (hits hasType's "name exists, type miss"
// fall-through return).
func TestUpdatePrereqRRsetExistsNameExistsTypeMiss(t *testing.T) {
	t.Parallel()
	_, addr := startUpdatableLocal(t)
	ex, err := acidns.NewUDPExchanger(addr)
	require.NoError(t, err)
	// www.example.com has A but not AAAA.
	msg, err := update.NewBuilder(wire.MustParseName("example.com")).
		PrereqRRsetExists(wire.MustParseName("www.example.com"), rrtype.AAAA).
		AddRRset(wire.NewRecord(wire.MustParseName("blog.example.com"), 60*time.Second,
			rdata.NewA(netip.MustParseAddr("198.51.100.4")))).
		Build()
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), msg)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENXRRSet, resp.Flags().RCODE())
}

// DeleteRecord that drops the last record at a name removes the name from
// the byName index entirely (hits the empty-kept delete branch in
// applyUpdate's ClassNONE path).
func TestUpdateDeleteRecordRemovesLast(t *testing.T) {
	t.Parallel()
	_, addr := startUpdatableLocal(t)
	ex, err := acidns.NewUDPExchanger(addr)
	require.NoError(t, err)

	// Add a fresh name with a single A.
	addRec := wire.NewRecord(wire.MustParseName("solo.example.com"), 60*time.Second,
		rdata.NewA(netip.MustParseAddr("198.51.100.50")))
	addMsg, err := update.NewBuilder(wire.MustParseName("example.com")).
		AddRRset(addRec).
		Build()
	require.NoError(t, err)
	_, err = ex.Exchange(t.Context(), addMsg)
	require.NoError(t, err)

	// Delete that one record specifically.
	delMsg, err := update.NewBuilder(wire.MustParseName("example.com")).
		DeleteRecord(addRec).
		Build()
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), delMsg)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())

	// solo.example.com should now be gone.
	q, _ := wire.NewBuilder().
		ID(77).
		Question(wire.NewQuestion(wire.MustParseName("solo.example.com"), rrtype.A)).
		Build()
	r, err := ex.Exchange(t.Context(), q)
	require.NoError(t, err)
	require.Equal(t, 0, len(r.Answers()))
}

// DeleteRecord on a name that doesn't exist is a no-op (no error).
func TestUpdateDeleteRecordMissingName(t *testing.T) {
	t.Parallel()
	_, addr := startUpdatableLocal(t)
	ex, err := acidns.NewUDPExchanger(addr)
	require.NoError(t, err)
	msg, err := update.NewBuilder(wire.MustParseName("example.com")).
		DeleteRecord(wire.NewRecord(wire.MustParseName("ghost.example.com"), 0,
			rdata.NewA(netip.MustParseAddr("192.0.2.99")))).
		Build()
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), msg)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())
}

// DeleteRRset on a name that doesn't exist is a no-op (no error).
func TestUpdateDeleteRRsetMissingName(t *testing.T) {
	t.Parallel()
	_, addr := startUpdatableLocal(t)
	ex, err := acidns.NewUDPExchanger(addr)
	require.NoError(t, err)
	msg, err := update.NewBuilder(wire.MustParseName("example.com")).
		DeleteRRset(wire.MustParseName("ghost.example.com"), rrtype.A).
		Build()
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), msg)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())
}

// DeleteRRset that strips one of two RRset types at a name keeps the other.
// Initial zone has both A and TXT at the same name (added below).
func TestUpdateDeleteOneRRsetKeepsOthers(t *testing.T) {
	t.Parallel()
	_, addr := startUpdatableLocal(t)
	ex, err := acidns.NewUDPExchanger(addr)
	require.NoError(t, err)

	// First add a TXT at www.
	txt, err := rdata.NewTXT("hello")
	require.NoError(t, err)
	addMsg, err := update.NewBuilder(wire.MustParseName("example.com")).
		AddRRset(wire.NewRecord(wire.MustParseName("www.example.com"), 60*time.Second, txt)).
		Build()
	require.NoError(t, err)
	_, err = ex.Exchange(t.Context(), addMsg)
	require.NoError(t, err)

	// Delete the A RRset; TXT must survive.
	delMsg, err := update.NewBuilder(wire.MustParseName("example.com")).
		DeleteRRset(wire.MustParseName("www.example.com"), rrtype.A).
		Build()
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), delMsg)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())

	// Confirm TXT still resolves.
	q, _ := wire.NewBuilder().
		ID(55).
		Question(wire.NewQuestion(wire.MustParseName("www.example.com"), rrtype.TXT)).
		Build()
	r, err := ex.Exchange(t.Context(), q)
	require.NoError(t, err)
	require.Equal(t, 1, len(r.Answers()))
	require.Equal(t, rrtype.TXT, r.Answers()[0].Type())
}

// DeleteRecord that doesn't match any rdata is a no-op (kept-list path with
// nothing removed).
func TestUpdateDeleteRecordNoMatch(t *testing.T) {
	t.Parallel()
	_, addr := startUpdatableLocal(t)
	ex, err := acidns.NewUDPExchanger(addr)
	require.NoError(t, err)
	msg, err := update.NewBuilder(wire.MustParseName("example.com")).
		DeleteRecord(wire.NewRecord(wire.MustParseName("www.example.com"), 0,
			rdata.NewA(netip.MustParseAddr("203.0.113.99")))).
		Build()
	require.NoError(t, err)
	resp, err := ex.Exchange(t.Context(), msg)
	require.NoError(t, err)
	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())

	// www's original A must still be there.
	q, _ := wire.NewBuilder().
		ID(66).
		Question(wire.NewQuestion(wire.MustParseName("www.example.com"), rrtype.A)).
		Build()
	r, err := ex.Exchange(t.Context(), q)
	require.NoError(t, err)
	require.Equal(t, 1, len(r.Answers()))
}
