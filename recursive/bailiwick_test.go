package recursive

import (
	"net/netip"
	"testing"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
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
			rdata.NewA(netip.MustParseAddr("192.0.2.1"))),
	}
	require.Len(t, glueFor(target, good, zone), 1)

	// A "glue" record whose owner is outside the delegating zone is
	// discarded — even if its name happens to match a target the
	// resolver is looking up. RFC 5452 §5.4.1: only in-bailiwick glue
	// is trustworthy.
	evilTarget := wire.MustParseName("evil.test")
	poisoned := []wire.Record{
		wire.NewRecord(evilTarget, 0,
			rdata.NewA(netip.MustParseAddr("198.51.100.1"))),
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
			rdata.NewA(netip.MustParseAddr("198.51.100.1"))),
	}
	got := recordsAt(records, cur)
	require.Len(t, got, 1, "only records owned by cur must survive")
	require.True(t, got[0].Name().Equal(cur))
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
