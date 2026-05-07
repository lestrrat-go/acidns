package update_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/update"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

func TestBuilderDeleteRRset(t *testing.T) {
	t.Parallel()
	msg, err := update.NewBuilder(wire.MustParseName("example.com")).
		DeleteRRset(wire.MustParseName("a.example.com"), rrtype.A).
		Build()
	require.NoError(t, err)
	require.Equal(t, 1, len(msg.Authorities()))
	auth := msg.Authorities()[0]
	require.Equal(t, rrtype.ClassANY, auth.Class())
	require.Equal(t, time.Duration(0), auth.TTL())
	require.Equal(t, rrtype.A, auth.Type())
}

func TestBuilderDeleteAll(t *testing.T) {
	t.Parallel()
	msg, err := update.NewBuilder(wire.MustParseName("example.com")).
		DeleteAll(wire.MustParseName("a.example.com")).
		Build()
	require.NoError(t, err)
	auth := msg.Authorities()[0]
	require.Equal(t, rrtype.ClassANY, auth.Class())
	require.Equal(t, rrtype.ANY, auth.Type())
}

func TestBuilderDeleteRecord(t *testing.T) {
	t.Parallel()
	rec := wire.NewRecord(wire.MustParseName("a.example.com"), 60*time.Second,
		rdata.NewA(netip.MustParseAddr("192.0.2.1")))
	msg, err := update.NewBuilder(wire.MustParseName("example.com")).
		DeleteRecord(rec).
		Build()
	require.NoError(t, err)
	auth := msg.Authorities()[0]
	require.Equal(t, rrtype.ClassNONE, auth.Class())
	require.Equal(t, rrtype.A, auth.Type())
}

func TestBuilderPrerequisites(t *testing.T) {
	t.Parallel()
	msg, err := update.NewBuilder(wire.MustParseName("example.com")).
		PrereqRRsetExists(wire.MustParseName("a.example.com"), rrtype.A).
		PrereqRRsetAbsent(wire.MustParseName("b.example.com"), rrtype.AAAA).
		PrereqNameInUse(wire.MustParseName("c.example.com")).
		PrereqNameNotInUse(wire.MustParseName("d.example.com")).
		Build()
	require.NoError(t, err)
	require.Equal(t, 4, len(msg.Answers()))

	a := msg.Answers()
	require.Equal(t, rrtype.ClassANY, a[0].Class()) // RRsetExists
	require.Equal(t, rrtype.A, a[0].Type())
	require.Equal(t, rrtype.ClassNONE, a[1].Class()) // RRsetAbsent
	require.Equal(t, rrtype.ClassANY, a[2].Class())  // NameInUse
	require.Equal(t, rrtype.ANY, a[2].Type())
	require.Equal(t, rrtype.ClassNONE, a[3].Class()) // NameNotInUse
	require.Equal(t, rrtype.ANY, a[3].Type())
}
