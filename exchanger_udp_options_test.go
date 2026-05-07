package acidns_test

import (
	"net/netip"
	"testing"

	"github.com/lestrrat-go/acidns"
	"github.com/stretchr/testify/require"
)

func TestNewWithReadBufferSize(t *testing.T) {
	t.Parallel()
	ex, err := acidns.NewUDPExchanger(netip.MustParseAddrPort("127.0.0.1:53"),
		acidns.WithUDPReadBufferSize(8192),
	)
	require.NoError(t, err)
	require.NotNil(t, ex)
}
