package wire_test

import (
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wiretest"
	"github.com/stretchr/testify/require"
)

func TestSortRecords_OwnerThenTypeThenRData(t *testing.T) {
	t.Parallel()
	a := wiretest.ARecord(wire.MustParseName("b.example.com"), time.Minute, "192.0.2.2")
	b := wiretest.ARecord(wire.MustParseName("a.example.com"), time.Minute, "192.0.2.5")
	c := wiretest.ARecord(wire.MustParseName("a.example.com"), time.Minute, "192.0.2.1")
	d := wiretest.AAAARecord(wire.MustParseName("a.example.com"), time.Minute, "2001:db8::1")

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
	q := wiretest.Query(wire.MustParseName("example.com"), rrtype.A)
	r1 := wiretest.ARecord(wire.MustParseName("example.com"), time.Minute, "192.0.2.1")
	r2 := wiretest.ARecord(wire.MustParseName("example.com"), time.Minute, "192.0.2.2")

	a := wiretest.Response(q, r1, r2)
	b := wiretest.Response(q, r2, r1)
	require.True(t, wire.MessageEqual(a, b))
}

func TestMessageEqual_DiffersOnRCODE(t *testing.T) {
	t.Parallel()
	q := wiretest.Query(wire.MustParseName("example.com"), rrtype.A)
	a := wiretest.Response(q)
	b := wiretest.NXDOMAIN(q)
	require.False(t, wire.MessageEqual(a, b))
}

func TestMessageEqual_DiffersOnRecordSet(t *testing.T) {
	t.Parallel()
	q := wiretest.Query(wire.MustParseName("example.com"), rrtype.A)
	r := wiretest.ARecord(wire.MustParseName("example.com"), time.Minute, "192.0.2.1")
	a := wiretest.Response(q)
	b := wiretest.Response(q, r)
	require.False(t, wire.MessageEqual(a, b))
}

func TestMessageEqual_DiffersOnTTL(t *testing.T) {
	t.Parallel()
	q := wiretest.Query(wire.MustParseName("example.com"), rrtype.A)
	r1 := wiretest.ARecord(wire.MustParseName("example.com"), time.Minute, "192.0.2.1")
	r2 := wiretest.ARecord(wire.MustParseName("example.com"), 2*time.Minute, "192.0.2.1")
	a := wiretest.Response(q, r1)
	b := wiretest.Response(q, r2)
	require.False(t, wire.MessageEqual(a, b))
}

func TestMessageEqual_EDNSOptionsOrderInsensitive(t *testing.T) {
	t.Parallel()
	q := wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)
	a, _ := wire.NewBuilder().
		ID(1).
		RecursionDesired(true).
		Question(q).
		EDNS(mustEDNS(t, wire.NewEDNSBuilder().UDPSize(1232).
			Option(wire.NewNSID(nil)).
			Option(wire.NewKeyTag(19036)))).
		Build()
	b, _ := wire.NewBuilder().
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
	a, _ := wire.NewBuilder().ID(1).Question(q).Build()
	b, _ := wire.NewBuilder().ID(1).Question(q).
		EDNS(mustEDNS(t, wire.NewEDNSBuilder().UDPSize(1232))).
		Build()
	require.False(t, wire.MessageEqual(a, b))
}
