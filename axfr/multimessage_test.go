package axfr_test

import (
	"context"
	"fmt"
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

// TestTransferLargeZone forces the server-side AXFR streamer to emit
// multiple length-framed messages by populating the zone with enough
// records to overflow a single 16 KB chunk.
func TestTransferLargeZone(t *testing.T) {
	t.Parallel()

	var sb strings.Builder
	sb.WriteString("$ORIGIN big.example.\n$TTL 60\n")
	sb.WriteString("@ IN SOA ns.big.example. hostmaster.big.example. ( 1 7200 3600 1209600 60 )\n")
	sb.WriteString("@ IN NS ns.big.example.\nns IN A 192.0.2.1\n")
	const recordCount = 4000
	for i := range recordCount {
		fmt.Fprintf(&sb, "h%05d IN A 192.0.2.%d\n", i, (i%250)+2)
	}

	z, err := zonefile.Parse(strings.NewReader(sb.String()))
	require.NoError(t, err)
	h, err := authoritative.New(
		authoritative.WithZone(z),
		authoritative.WithAXFRPolicy(func(_ context.Context, _ acidns.ResponseWriter, _ wire.Message) bool { return true }),
	)
	require.NoError(t, err)

	srv, err := acidns.NewTCPServer(netip.MustParseAddrPort("127.0.0.1:0"), h)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	ctrl, err := srv.Run(ctx)

	require.NoError(t, err)

	xferCtx, xcancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer xcancel()
	ex, err := acidns.NewTCPExchanger(ctrl.Addr())
	require.NoError(t, err)
	xfer, err := axfr.Start(xferCtx, ex, wire.MustParseName("big.example"))
	require.NoError(t, err)
	defer func() { _ = xfer.Close() }()

	var records []wire.Record
	for {
		ev, err := xfer.Next(xferCtx)
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		records = append(records, ev.Record())
	}

	// Expect SOA + NS + 1 A glue + recordCount A records + trailing SOA.
	require.GreaterOrEqual(t, len(records), recordCount+3)
	require.Equal(t, rrtype.SOA, records[0].Type())
	require.Equal(t, rrtype.SOA, records[len(records)-1].Type())

	var aCount int
	for _, r := range records {
		if r.Type() == rrtype.A {
			aCount++
		}
	}
	// recordCount synthetic + 1 glue
	require.GreaterOrEqual(t, aCount, recordCount)
}
