package authoritative_test

import (
	"context"
	"testing"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

func TestEDNSOPTEchoOnAnswer(t *testing.T) {
	t.Parallel()
	a := newAuth(t)

	q, err := wire.NewBuilder().
		ID(99).
		RecursionDesired(true).
		Question(wire.NewQuestion(wire.MustParseName("www.example.com"), rrtype.A)).
		EDNS(wire.NewEDNSBuilder().UDPSize(4096).DO(true).Build()).
		Build()
	require.NoError(t, err)

	w := &inProcWriter{}
	a.ServeDNS(context.Background(), w, q)

	e, ok := w.resp.EDNS()
	require.True(t, ok, "RFC 6891 §6.1.1: EDNS-aware response MUST contain OPT")
	require.NotNil(t, e)
	require.True(t, e.DO(), "DO bit must be mirrored from the request")
}

func TestEDNSOPTAbsentWhenRequestHasNoOPT(t *testing.T) {
	t.Parallel()
	a := newAuth(t)
	resp := ask(t, a, "www.example.com", rrtype.A)
	_, ok := resp.EDNS()
	require.False(t, ok, "non-EDNS query must not get an OPT in response")
}

func TestEDNSOPTEchoOnRefusedNoZone(t *testing.T) {
	t.Parallel()
	a := newAuth(t)

	q, err := wire.NewBuilder().
		ID(123).
		Question(wire.NewQuestion(wire.MustParseName("not-our-zone.test"), rrtype.A)).
		EDNS(wire.NewEDNSBuilder().UDPSize(1232).Build()).
		Build()
	require.NoError(t, err)

	w := &inProcWriter{}
	a.ServeDNS(context.Background(), w, q)

	require.Equal(t, wire.RCODERefused, w.resp.Flags().RCODE())
	_, ok := w.resp.EDNS()
	require.True(t, ok, "REFUSED response must still echo OPT when request had OPT")
}
