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
