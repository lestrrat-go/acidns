package udp_test

import (
	"net/netip"
	"testing"

	"github.com/lestrrat-go/acidns/dnsclient/transport/udp"
	"github.com/stretchr/testify/require"
)

func TestNewWithReadBufferSize(t *testing.T) {
	t.Parallel()
	ex, err := udp.New(netip.MustParseAddrPort("127.0.0.1:53"),
		udp.WithReadBufferSize(8192),
	)
	require.NoError(t, err)
	require.NotNil(t, ex)
}
