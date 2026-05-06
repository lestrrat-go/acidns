package dnsmsg_test

import (
	"strings"
	"testing"

	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/stretchr/testify/require"
)

func TestReportChannel(t *testing.T) {
	t.Parallel()
	o := dnsmsg.NewReportChannel(dnsname.MustParse("agent.example.net"))
	got, ok := dnsmsg.ReportChannelAgent(o)
	require.True(t, ok)
	require.True(t, got.Equal(dnsname.MustParse("agent.example.net")))
}

func TestBuildErrorReportName(t *testing.T) {
	t.Parallel()
	n, err := dnsmsg.BuildErrorReportName(
		dnsname.MustParse("broken.example.com"),
		rrtype.A,
		dnsmsg.ExtendedErrorDNSSECBogus,
		dnsname.MustParse("agent.example.net"),
	)
	require.NoError(t, err)
	s := n.String()
	require.True(t, strings.HasPrefix(s, "_er.1.broken.example.com.6._er.agent.example.net."))
}

func TestBuildErrorReportRejectsRoot(t *testing.T) {
	t.Parallel()
	_, err := dnsmsg.BuildErrorReportName(
		dnsname.MustParse("."),
		rrtype.A,
		dnsmsg.ExtendedErrorOther,
		dnsname.MustParse("agent.example.net"),
	)
	require.Error(t, err)
}
