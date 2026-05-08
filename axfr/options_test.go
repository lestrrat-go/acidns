package axfr_test

import (
	"context"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/authoritative"
	"github.com/lestrrat-go/acidns/axfr"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/zonefile"
	"github.com/stretchr/testify/require"
)

func TestStartWithTimeoutAndNewSOA(t *testing.T) {
	t.Parallel()
	z, err := zonefile.Parse(strings.NewReader(transferZone))
	require.NoError(t, err)
	h, err := authoritative.New(authoritative.WithZone(z))
	require.NoError(t, err)
	srv, err := acidns.NewTCPServer(netip.MustParseAddrPort("127.0.0.1:0"), h)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)

	require.NoError(t, err)

	xferCtx, xcancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer xcancel()
	xfer, err := axfr.Start(xferCtx, newStreamEx(t, ctrl.Addr()),
		wire.MustParseName("example.com"),
		axfr.WithTimeout(2*time.Second))
	require.NoError(t, err)
	defer func() { _ = xfer.Close() }()

	soa := xfer.NewSOA()
	require.NotNil(t, soa)
	require.Equal(t, uint32(2024010100), soa.Serial())

	// Drain at least once to ensure the stream emits records.
	ev, err := xfer.Next(xferCtx)
	require.NoError(t, err)
	require.Equal(t, rrtype.SOA, ev.Record().Type())

	// Drain the rest.
	for {
		_, err := xfer.Next(xferCtx)
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
	}
}
