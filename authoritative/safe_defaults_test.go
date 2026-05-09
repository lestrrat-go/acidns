package authoritative_test

import (
	"context"
	"strings"
	"testing"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/authoritative"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/zonefile"
	"github.com/stretchr/testify/require"
)

// TestAXFRRefusedWithoutPolicy verifies the safe default: AXFR over
// TCP for a hosted zone is REFUSED unless WithAXFRPolicy is supplied.
// Without this default, a server with split-horizon zones would leak
// every record to any TCP peer.
func TestAXFRRefusedWithoutPolicy(t *testing.T) {
	t.Parallel()
	z, err := zonefile.Parse(strings.NewReader(sampleZone))
	require.NoError(t, err)
	a, err := authoritative.New(authoritative.WithZone(z))
	require.NoError(t, err)

	q, err := wire.NewMessageBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.AXFR)).
		Build()
	require.NoError(t, err)
	w := &inProcWriter{network: "tcp"}
	a.ServeDNS(context.Background(), w, q)
	require.NotNil(t, w.resp)
	require.Equal(t, wire.RCODERefused, w.resp.Flags().RCODE())
}

// TestAXFRRefusedWhenPolicyDenies verifies the policy is consulted when
// installed, and a deny verdict produces REFUSED.
func TestAXFRRefusedWhenPolicyDenies(t *testing.T) {
	t.Parallel()
	z, err := zonefile.Parse(strings.NewReader(sampleZone))
	require.NoError(t, err)
	deny := func(_ context.Context, _ acidns.ResponseWriter, _ wire.Message) bool { return false }
	a, err := authoritative.New(
		authoritative.WithZone(z),
		authoritative.WithAXFRPolicy(deny),
	)
	require.NoError(t, err)

	q, err := wire.NewMessageBuilder().
		ID(1).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.AXFR)).
		Build()
	require.NoError(t, err)
	w := &inProcWriter{network: "tcp"}
	a.ServeDNS(context.Background(), w, q)
	require.Equal(t, wire.RCODERefused, w.resp.Flags().RCODE())
}

// TestNotifyRefusedWithoutPolicy verifies the safe default: NOTIFY for
// a hosted zone is REFUSED unless WithNotifyPolicy is supplied.
func TestNotifyRefusedWithoutPolicy(t *testing.T) {
	t.Parallel()
	z, err := zonefile.Parse(strings.NewReader(sampleZone))
	require.NoError(t, err)
	a, err := authoritative.New(authoritative.WithZone(z))
	require.NoError(t, err)

	q, err := wire.NewMessageBuilder().
		ID(1).
		Opcode(wire.OpcodeNotify).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.SOA)).
		Build()
	require.NoError(t, err)
	w := &inProcWriter{network: "udp"}
	a.ServeDNS(context.Background(), w, q)
	require.NotNil(t, w.resp)
	require.Equal(t, wire.RCODERefused, w.resp.Flags().RCODE())
}
