package dnsupdate_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient/dnsupdate"
	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/stretchr/testify/require"
)

func TestBuilderDeleteRRset(t *testing.T) {
	t.Parallel()
	msg, err := dnsupdate.NewBuilder(dnsname.MustParse("example.com")).
		DeleteRRset(dnsname.MustParse("a.example.com"), rrtype.A).
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
	msg, err := dnsupdate.NewBuilder(dnsname.MustParse("example.com")).
		DeleteAll(dnsname.MustParse("a.example.com")).
		Build()
	require.NoError(t, err)
	auth := msg.Authorities()[0]
	require.Equal(t, rrtype.ClassANY, auth.Class())
	require.Equal(t, rrtype.ANY, auth.Type())
}

func TestBuilderDeleteRecord(t *testing.T) {
	t.Parallel()
	rec := dnsmsg.NewRecord(dnsname.MustParse("a.example.com"), 60*time.Second,
		rdata.NewA(netip.MustParseAddr("192.0.2.1")))
	msg, err := dnsupdate.NewBuilder(dnsname.MustParse("example.com")).
		DeleteRecord(rec).
		Build()
	require.NoError(t, err)
	auth := msg.Authorities()[0]
	require.Equal(t, rrtype.ClassNONE, auth.Class())
	require.Equal(t, rrtype.A, auth.Type())
}

func TestBuilderPrerequisites(t *testing.T) {
	t.Parallel()
	msg, err := dnsupdate.NewBuilder(dnsname.MustParse("example.com")).
		PrereqRRsetExists(dnsname.MustParse("a.example.com"), rrtype.A).
		PrereqRRsetAbsent(dnsname.MustParse("b.example.com"), rrtype.AAAA).
		PrereqNameInUse(dnsname.MustParse("c.example.com")).
		PrereqNameNotInUse(dnsname.MustParse("d.example.com")).
		Build()
	require.NoError(t, err)
	require.Equal(t, 4, len(msg.Answers()))

	a := msg.Answers()
	require.Equal(t, rrtype.ClassANY, a[0].Class()) // RRsetExists
	require.Equal(t, rrtype.A, a[0].Type())
	require.Equal(t, rrtype.ClassNONE, a[1].Class()) // RRsetAbsent
	require.Equal(t, rrtype.ClassANY, a[2].Class()) // NameInUse
	require.Equal(t, rrtype.ANY, a[2].Type())
	require.Equal(t, rrtype.ClassNONE, a[3].Class()) // NameNotInUse
	require.Equal(t, rrtype.ANY, a[3].Type())
}
