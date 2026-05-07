package wire_test

import (
	"strings"
	"testing"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
	"github.com/stretchr/testify/require"
)

func TestReportChannel(t *testing.T) {
	t.Parallel()
	o := wire.NewReportChannel(wirebb.MustParse("agent.example.net"))
	got, ok := wire.ReportChannelAgent(o)
	require.True(t, ok)
	require.True(t, got.Equal(wirebb.MustParse("agent.example.net")))
}

func TestBuildErrorReportName(t *testing.T) {
	t.Parallel()
	n, err := wire.BuildErrorReportName(
		wirebb.MustParse("broken.example.com"),
		rrtype.A,
		wire.ExtendedErrorDNSSECBogus,
		wirebb.MustParse("agent.example.net"),
	)
	require.NoError(t, err)
	s := n.String()
	require.True(t, strings.HasPrefix(s, "_er.1.broken.example.com.6._er.agent.example.net."))
}

func TestBuildErrorReportRejectsRoot(t *testing.T) {
	t.Parallel()
	_, err := wire.BuildErrorReportName(
		wirebb.MustParse("."),
		rrtype.A,
		wire.ExtendedErrorOther,
		wirebb.MustParse("agent.example.net"),
	)
	require.Error(t, err)
}
