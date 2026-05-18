package wire_test

import (
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/internal/wiretest"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

func TestSortRecords_OwnerThenTypeThenRData(t *testing.T) {
	t.Parallel()
	a, err := wiretest.ARecord(wire.MustParseName("b.example.com"), time.Minute, "192.0.2.2")
	require.NoError(t, err)
	b, err := wiretest.ARecord(wire.MustParseName("a.example.com"), time.Minute, "192.0.2.5")
	require.NoError(t, err)
	c, err := wiretest.ARecord(wire.MustParseName("a.example.com"), time.Minute, "192.0.2.1")
	require.NoError(t, err)
	d, err := wiretest.AAAARecord(wire.MustParseName("a.example.com"), time.Minute, "2001:db8::1")
	require.NoError(t, err)

	in := []wire.Record{a, b, c, d}
	wire.SortRecords(in)

	// Expected order: a/A 192.0.2.1, a/A 192.0.2.5, a/AAAA, b/A 192.0.2.2.
	require.Equal(t, "a.example.com.", in[0].Name().String())
	require.Equal(t, rrtype.A, in[0].Type())
	require.Equal(t, "a.example.com.", in[1].Name().String())
	require.Equal(t, rrtype.A, in[1].Type())
	require.Equal(t, "a.example.com.", in[2].Name().String())
	require.Equal(t, rrtype.AAAA, in[2].Type())
	require.Equal(t, "b.example.com.", in[3].Name().String())
}

func TestMessageEqual_OrderInsensitive(t *testing.T) {
	t.Parallel()
	q, err := wiretest.Query(wire.MustParseName("example.com"), rrtype.A)
	require.NoError(t, err)
	r1, err := wiretest.ARecord(wire.MustParseName("example.com"), time.Minute, "192.0.2.1")
	require.NoError(t, err)
	r2, err := wiretest.ARecord(wire.MustParseName("example.com"), time.Minute, "192.0.2.2")
	require.NoError(t, err)

	a, err := wiretest.Response(q, r1, r2)
	require.NoError(t, err)
	b, err := wiretest.Response(q, r2, r1)
	require.NoError(t, err)
	require.True(t, wire.MessageEqual(a, b))
}

func TestMessageEqual_DiffersOnRCODE(t *testing.T) {
	t.Parallel()
	q, err := wiretest.Query(wire.MustParseName("example.com"), rrtype.A)
	require.NoError(t, err)
	a, err := wiretest.Response(q)
	require.NoError(t, err)
	b, err := wiretest.NXDOMAIN(q)
	require.NoError(t, err)
	require.False(t, wire.MessageEqual(a, b))
}

func TestMessageEqual_DiffersOnRecordSet(t *testing.T) {
	t.Parallel()
	q, err := wiretest.Query(wire.MustParseName("example.com"), rrtype.A)
	require.NoError(t, err)
	r, err := wiretest.ARecord(wire.MustParseName("example.com"), time.Minute, "192.0.2.1")
	require.NoError(t, err)
	a, err := wiretest.Response(q)
	require.NoError(t, err)
	b, err := wiretest.Response(q, r)
	require.NoError(t, err)
	require.False(t, wire.MessageEqual(a, b))
}

func TestMessageEqual_DiffersOnTTL(t *testing.T) {
	t.Parallel()
	q, err := wiretest.Query(wire.MustParseName("example.com"), rrtype.A)
	require.NoError(t, err)
	r1, err := wiretest.ARecord(wire.MustParseName("example.com"), time.Minute, "192.0.2.1")
	require.NoError(t, err)
	r2, err := wiretest.ARecord(wire.MustParseName("example.com"), 2*time.Minute, "192.0.2.1")
	require.NoError(t, err)
	a, err := wiretest.Response(q, r1)
	require.NoError(t, err)
	b, err := wiretest.Response(q, r2)
	require.NoError(t, err)
	require.False(t, wire.MessageEqual(a, b))
}

func TestMessageEqual_EDNSOptionsOrderInsensitive(t *testing.T) {
	t.Parallel()
	q := wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)
	a, _ := wire.NewMessageBuilder().
		ID(1).
		RecursionDesired(true).
		Question(q).
		EDNS(mustEDNS(t, wire.NewEDNSBuilder().UDPSize(1232).
			Option(wire.NewNSID(nil)).
			Option(wire.NewKeyTag(19036)))).
		Build()
	b, _ := wire.NewMessageBuilder().
		ID(1).
		RecursionDesired(true).
		Question(q).
		EDNS(mustEDNS(t, wire.NewEDNSBuilder().UDPSize(1232).
			Option(wire.NewKeyTag(19036)).
			Option(wire.NewNSID(nil)))).
		Build()
	require.True(t, wire.MessageEqual(a, b))
}

func TestMessageEqual_DiffersOnEDNSPresence(t *testing.T) {
	t.Parallel()
	q := wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)
	a, _ := wire.NewMessageBuilder().ID(1).Question(q).Build()
	b, _ := wire.NewMessageBuilder().ID(1).Question(q).
		EDNS(mustEDNS(t, wire.NewEDNSBuilder().UDPSize(1232))).
		Build()
	require.False(t, wire.MessageEqual(a, b))
}
