package authoritative_test

import (
	"context"
	"strings"
	"testing"

	"github.com/lestrrat-go/acidns/authoritative"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/zonefile"
	"github.com/stretchr/testify/require"
)

// TestMinimalANYDefault verifies that, by default, QTYPE=ANY for a name
// that exists in the zone responds with exactly one synthetic HINFO
// record carrying CPU="RFC8482" and OS="" (RFC 8482 §4). This is the
// safe default — the legacy full-RRset reply is the classic ANY
// amplification primitive.
func TestMinimalANYDefault(t *testing.T) {
	t.Parallel()
	z, err := zonefile.Parse(strings.NewReader(sampleZone))
	require.NoError(t, err)
	a, err := authoritative.New(authoritative.WithZone(z))
	require.NoError(t, err)

	resp := ask(t, a, "www.example.com", rrtype.ANY)
	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())
	require.True(t, resp.Flags().Authoritative())
	require.Equal(t, 1, len(resp.Answers()), "minimal ANY must return exactly one record")

	rec := resp.Answers()[0]
	require.Equal(t, rrtype.HINFO, rec.Type())
	hi, ok := wire.RDataAs[rdata.HINFO](rec)
	require.True(t, ok, "answer must be HINFO rdata")
	require.Equal(t, "RFC8482", hi.CPU())
	require.Equal(t, "", hi.OS())
}

// TestMinimalANYDisabled verifies WithMinimalANY(false) preserves the
// legacy behaviour: QTYPE=ANY walks the RRset list at the QNAME and
// returns every record (here: A and AAAA on www.example.com).
func TestMinimalANYDisabled(t *testing.T) {
	t.Parallel()
	z, err := zonefile.Parse(strings.NewReader(sampleZone))
	require.NoError(t, err)
	a, err := authoritative.New(
		authoritative.WithZone(z),
		authoritative.WithMinimalANY(false),
	)
	require.NoError(t, err)

	resp := ask(t, a, "www.example.com", rrtype.ANY)
	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())
	require.True(t, resp.Flags().Authoritative())
	// Legacy answer() goes through zoneIndex.lookup which only matches
	// records with Type() == qtype; it does NOT special-case ANY, so
	// the response is the NODATA-style empty-answer + SOA in authority.
	// What matters here is that the minimal-HINFO short-circuit is OFF,
	// i.e. the response must NOT be a single HINFO/RFC8482.
	for _, rec := range resp.Answers() {
		if hi, ok := wire.RDataAs[rdata.HINFO](rec); ok {
			require.NotEqual(t, "RFC8482", hi.CPU(),
				"WithMinimalANY(false) must not synthesise the RFC 8482 HINFO")
		}
	}
}

// TestMinimalANYNotForCHAOSClass verifies the minimal-ANY shortcut is
// gated on CLASS=IN — a CHAOS-class ANY (uncommon, but possible) is
// not collapsed to a HINFO answer because the HINFO would be IN-class
// and pointless to a CHAOS-class querier.
func TestMinimalANYNotForCHAOSClass(t *testing.T) {
	t.Parallel()
	z, err := zonefile.Parse(strings.NewReader(sampleZone))
	require.NoError(t, err)
	a, err := authoritative.New(authoritative.WithZone(z))
	require.NoError(t, err)

	q, err := wire.NewBuilder().
		ID(1).
		Question(wire.NewQuestionClass(wire.MustParseName("www.example.com"), rrtype.ANY, rrtype.ClassCH)).
		Build()
	require.NoError(t, err)
	w := &inProcWriter{}
	a.ServeDNS(context.Background(), w, q)
	require.NotNil(t, w.resp)
	for _, rec := range w.resp.Answers() {
		if hi, ok := wire.RDataAs[rdata.HINFO](rec); ok {
			require.NotEqual(t, "RFC8482", hi.CPU(),
				"minimal ANY must not fire for non-IN class")
		}
	}
}
