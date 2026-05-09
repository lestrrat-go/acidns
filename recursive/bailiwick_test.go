package recursive

import (
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

func TestInBailiwick(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ancestor   string
		descendant string
		want       bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "www.example.com", true},
		{"example.com", "a.b.example.com", true},
		{"example.com", "evil.test", false},
		{"example.com", "com", false},
	}
	for _, tc := range tests {
		t.Run(tc.ancestor+"<-"+tc.descendant, func(t *testing.T) {
			t.Parallel()
			got := inBailiwick(wire.MustParseName(tc.ancestor), wire.MustParseName(tc.descendant))
			require.Equal(t, tc.want, got)
		})
	}
}

func TestGlueForRejectsOutOfBailiwickAdditional(t *testing.T) {
	t.Parallel()
	zone := wire.MustParseName("example.com")
	target := wire.MustParseName("ns.example.com")

	// In-bailiwick glue is accepted.
	good := []wire.Record{
		wire.NewRecord(target, 0,
			rdata.MustNewA(netip.MustParseAddr("192.0.2.1"))),
	}
	require.Len(t, glueFor(target, good, zone), 1)

	// A "glue" record whose owner is outside the delegating zone is
	// discarded — even if its name happens to match a target the
	// resolver is looking up. RFC 5452 §5.4.1: only in-bailiwick glue
	// is trustworthy.
	evilTarget := wire.MustParseName("evil.test")
	poisoned := []wire.Record{
		wire.NewRecord(evilTarget, 0,
			rdata.MustNewA(netip.MustParseAddr("198.51.100.1"))),
	}
	require.Empty(t, glueFor(evilTarget, poisoned, zone),
		"glue for out-of-bailiwick name must be rejected")
}

func TestRecordsAtFiltersByOwner(t *testing.T) {
	t.Parallel()
	cur := wire.MustParseName("evil.example")
	other := wire.MustParseName("victim.bank.com")

	records := []wire.Record{
		// Legitimate record at the queried name.
		wire.NewRecord(cur, 60, rdata.NewCNAME(other)),
		// Forged record bundled by a malicious authoritative.
		wire.NewRecord(other, 60,
			rdata.MustNewA(netip.MustParseAddr("198.51.100.1"))),
	}
	got := recordsAt(records, cur)
	require.Len(t, got, 1, "only records owned by cur must survive")
	require.True(t, got[0].Name().Equal(cur))
}

// TestEntryFromResponseCapsNegativeTTL confirms that a hostile or
// misconfigured zone with a multi-year SOA MINIMUM cannot pin an
// NXDOMAIN/NoData entry past the configured maxNegTTL. RFC 2308 §4
// caps negative caching at 24 hours; the resolver's default is 1 hour.
func TestEntryFromResponseCapsNegativeTTL(t *testing.T) {
	t.Parallel()
	r := &Recursive{maxNegTTL: time.Hour}

	soa := wire.NewRecord(wire.MustParseName("evil.example."), 365*24*time.Hour,
		rdata.MustNewSOA(
			wire.MustParseName("ns.evil.example."),
			wire.MustParseName("hm.evil.example."),
			1, 7200, 3600, 1209600,
			365*24*time.Hour, // SOA MINIMUM = 1 year
		))

	resp, err := wire.NewBuilder().
		ID(1).
		Response(true).
		RCODE(wire.RCODENXDomain).
		Question(wire.NewQuestion(wire.MustParseName("ghost.evil.example."), rrtype.A)).
		Authority(soa).
		Build()
	require.NoError(t, err)

	before := time.Now()
	entry := r.entryFromResponse(wire.MustParseName("ghost.evil.example."), resp)
	require.LessOrEqual(t, entry.ExpiresAt().Sub(before), time.Hour+time.Second,
		"negative TTL must be clamped to maxNegTTL regardless of SOA MINIMUM")
}

// TestBailiwickFilterDropsForgedAnswerRecords reproduces the off-path
// cache poisoning vector where a malicious authoritative for `evil.example`
// stuffs the answer/authority/additional sections of a query for
// `www.evil.example` with records for `bank.com`. The resolver must not
// cache or surface those records to the caller.
func TestBailiwickFilterDropsForgedAnswerRecords(t *testing.T) {
	t.Parallel()
	qname := wire.MustParseName("www.evil.example.")

	good := wire.NewRecord(qname, 60*time.Second,
		rdata.MustNewA(netip.MustParseAddr("198.51.100.1")))
	forgedAnswer := wire.NewRecord(wire.MustParseName("bank.com."), 60*time.Second,
		rdata.MustNewA(netip.MustParseAddr("203.0.113.1")))
	forgedAuthority := wire.NewRecord(wire.MustParseName("bank.com."), 60*time.Second,
		rdata.NewNS(wire.MustParseName("ns.evil.example.")))
	forgedAdditional := wire.NewRecord(wire.MustParseName("bank.com."), 60*time.Second,
		rdata.MustNewA(netip.MustParseAddr("203.0.113.2")))
	zoneNS := wire.NewRecord(wire.MustParseName("evil.example."), 60*time.Second,
		rdata.NewNS(wire.MustParseName("ns.evil.example.")))

	resp, err := wire.NewBuilder().
		ID(1).
		Response(true).
		Authoritative(true).
		Question(wire.NewQuestion(qname, rrtype.A)).
		Answer(good).
		Answer(forgedAnswer).
		Authority(zoneNS).
		Authority(forgedAuthority).
		Additional(forgedAdditional).
		Build()
	require.NoError(t, err)

	answers, authority, additional := bailiwickFilter(qname, resp)

	require.Len(t, answers, 1)
	require.True(t, answers[0].Name().Equal(qname))

	for _, r := range authority {
		require.True(t, inBailiwick(r.Name(), qname),
			"authority record %s out of bailiwick for %s", r.Name(), qname)
	}
	for _, r := range additional {
		require.NotEqual(t, "bank.com.", r.Name().String(),
			"forged additional must be dropped")
	}
}

func TestReferralZone(t *testing.T) {
	t.Parallel()
	rec := wire.NewRecord(wire.MustParseName("example.com"), 0,
		rdata.NewNS(wire.MustParseName("ns1.example.com")))
	resp, err := wire.NewBuilder().Authority(rec).Build()
	require.NoError(t, err)
	z := referralZone(resp)
	require.True(t, z.Equal(wire.MustParseName("example.com")))
}
