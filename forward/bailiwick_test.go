package forward

import (
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// TestFilterBailiwickDropsForgedAnswerRecords verifies the filter
// drops Answer records whose owner is unrelated to qname — the
// Kashpureff-style cache poisoning vector.
func TestFilterBailiwickDropsForgedAnswerRecords(t *testing.T) {
	qname := wire.MustParseName("legit.example.")
	ar2, err := rdata.NewA(netip.MustParseAddr("198.51.100.99"))
	require.NoError(t, err)
	ar, err := rdata.NewA(netip.MustParseAddr("192.0.2.1"))
	require.NoError(t, err)
	resp, err := wire.NewMessageBuilder().
		ID(1).
		Response(true).
		Question(wire.NewQuestion(qname, rrtype.A)).
		Answer(wire.NewRecord(qname, time.Hour,
			ar)).
		// Forged record for an unrelated name.
		Answer(wire.NewRecord(wire.MustParseName("unrelated.evil."), time.Hour,
			ar2)).
		Build()
	require.NoError(t, err)

	out := filterBailiwick(qname, resp)
	require.Equal(t, 1, len(out.Answers()))
	require.True(t, out.Answers()[0].Name().Equal(qname))
}

// TestFilterBailiwickKeepsCNAMEChain verifies the chain-following
// behaviour: a target reached transitively via CNAME is in-scope.
func TestFilterBailiwickKeepsCNAMEChain(t *testing.T) {
	qname := wire.MustParseName("alias.example.")
	target := wire.MustParseName("real.example.")
	ar4, err := rdata.NewA(netip.MustParseAddr("198.51.100.99"))
	require.NoError(t, err)
	ar3, err := rdata.NewA(netip.MustParseAddr("192.0.2.1"))
	require.NoError(t, err)
	cn, err := rdata.NewCNAME(target)
	require.NoError(t, err)
	resp, err := wire.NewMessageBuilder().
		ID(1).
		Response(true).
		Question(wire.NewQuestion(qname, rrtype.A)).
		Answer(wire.NewRecord(qname, time.Hour, cn)).
		Answer(wire.NewRecord(target, time.Hour,
			ar3)).
		// Off-chain record dropped.
		Answer(wire.NewRecord(wire.MustParseName("other.evil."), time.Hour,
			ar4)).
		Build()
	require.NoError(t, err)

	out := filterBailiwick(qname, resp)
	require.Equal(t, 2, len(out.Answers()))
}

// TestFilterBailiwickDropsRootOwnedAuthority verifies that authority
// records owned at the DNS root are rejected when qname is not the
// root itself. A compromised upstream answering "bank.example." with
// SOA owned at "." plus crafted NSEC records covering the qname would
// otherwise satisfy the at-or-above ancestor check and reach the
// cache; the forwarder has no validator behind it, so the records
// must be filtered up front.
func TestFilterBailiwickDropsRootOwnedAuthority(t *testing.T) {
	qname := wire.MustParseName("bank.example.")
	root := wire.MustParseName(".")
	soa, err := rdata.NewSOA(
		wire.MustParseName("ns.evil."),
		wire.MustParseName("hostmaster.evil."),
		1,
		3600*time.Second,
		600*time.Second,
		86400*time.Second,
		300*time.Second,
	)
	require.NoError(t, err)
	// A crafted NSEC owned at the victim qname — same shape an
	// attacker would use to manufacture an NXDOMAIN-like denial.
	nsec := rdata.NewNSEC(
		wire.MustParseName("nextdomain.evil."),
		[]rrtype.Type{rrtype.A, rrtype.AAAA},
	)
	resp, err := wire.NewMessageBuilder().
		ID(1).
		Response(true).
		Question(wire.NewQuestion(qname, rrtype.A)).
		Authority(wire.NewRecord(root, time.Hour, soa)).
		Authority(wire.NewRecord(qname, time.Hour, nsec)).
		Build()
	require.NoError(t, err)

	out := filterBailiwick(qname, resp)
	for _, r := range out.Authorities() {
		require.False(t, r.Name().IsRoot(),
			"root-owned authority record must be rejected for non-root qname")
		require.NotEqual(t, rrtype.SOA, r.Type(),
			"forged root-owned SOA must not reach the filtered output")
	}
}

// TestFilterBailiwickKeepsRootOwnedAuthorityForRootQuery verifies the
// root-owner rejection only applies when qname is below the root; a
// genuine root query (e.g. "." NS) must still see root-owned authority
// records pass through.
func TestFilterBailiwickKeepsRootOwnedAuthorityForRootQuery(t *testing.T) {
	root := wire.MustParseName(".")
	nsrd, err := rdata.NewNS(wire.MustParseName("a.root-servers.net."))
	require.NoError(t, err)
	resp, err := wire.NewMessageBuilder().
		ID(1).
		Response(true).
		Question(wire.NewQuestion(root, rrtype.NS)).
		Authority(wire.NewRecord(root, time.Hour, nsrd)).
		Build()
	require.NoError(t, err)

	out := filterBailiwick(root, resp)
	require.Equal(t, 1, len(out.Authorities()))
	require.True(t, out.Authorities()[0].Name().IsRoot())
}

// TestFilterBailiwickDropsOutOfBailiwickAuthority verifies authority
// records owned by unrelated parent zones are removed.
func TestFilterBailiwickDropsOutOfBailiwickAuthority(t *testing.T) {
	qname := wire.MustParseName("a.example.")
	nsrd2, err := rdata.NewNS(wire.MustParseName("ns1.evil."))
	require.NoError(t, err)
	nsrd, err := rdata.NewNS(wire.MustParseName("ns1.example."))
	require.NoError(t, err)
	resp, err := wire.NewMessageBuilder().
		ID(1).
		Response(true).
		Question(wire.NewQuestion(qname, rrtype.A)).
		Authority(wire.NewRecord(wire.MustParseName("example."), time.Hour,
			nsrd)).
		Authority(wire.NewRecord(wire.MustParseName("evil."), time.Hour,
			nsrd2)).
		Build()
	require.NoError(t, err)

	out := filterBailiwick(qname, resp)
	require.Equal(t, 1, len(out.Authorities()))
	require.True(t, out.Authorities()[0].Name().Equal(wire.MustParseName("example.")))
}
