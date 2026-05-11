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
	ar, err := rdata.NewA(netip.MustParseAddr("192.0.2.1"))
	require.NoError(t, err)
	rec := wire.NewRecord(wire.MustParseName("a.example.com"), 60*time.Second,
		ar)
	msg, err := update.NewBuilder(wire.MustParseName("example.com")).
		DeleteRecord(rec).
		Build()
	require.NoError(t, err)
	auth := msg.Authorities()[0]
	require.Equal(t, rrtype.ClassNONE, auth.Class())
	require.Equal(t, rrtype.A, auth.Type())
}

// TestBuilderSingleShot verifies that Builder.Build resets prereq /
// update queues so a second build does not carry over records from
// the first. (The zone is supplied via NewBuilder and is intentionally
// not retained across builds.)
func TestBuilderSingleShot(t *testing.T) {
	t.Parallel()
	b := update.NewBuilder(wire.MustParseName("example.com")).
		DeleteRRset(wire.MustParseName("a.example.com"), rrtype.A).
		PrereqNameInUse(wire.MustParseName("a.example.com"))

	first, err := b.Build()
	require.NoError(t, err)
	require.Equal(t, 1, len(first.Authorities()))
	require.Equal(t, 1, len(first.Answers()))

	// Second build off the same builder must produce a fresh empty
	// message (no carryover) — Build resets prereqs/updates.
	second, err := b.Build()
	require.NoError(t, err)
	require.Equal(t, 0, len(second.Authorities()), "reset must clear updates")
	require.Equal(t, 0, len(second.Answers()), "reset must clear prereqs")

	// First build's slices are unaffected.
	require.Equal(t, 1, len(first.Authorities()))
	require.Equal(t, 1, len(first.Answers()))
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
