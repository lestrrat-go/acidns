//go:build acidns_no_doq

package doq_test

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/doq"
	"github.com/stretchr/testify/require"
)

func TestNew_ReturnsErrDoQDisabled(t *testing.T) {
	t.Parallel()
	_, err := doq.New(
		netip.MustParseAddrPort("127.0.0.1:8853"),
		doq.WithTimeout(time.Second),
		doq.WithServerName("example.com"),
	)
	require.Error(t, err)
	require.True(t, errors.Is(err, doq.ErrDoQDisabled))
}
