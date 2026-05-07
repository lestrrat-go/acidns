package wire_test

import (
	"testing"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
	"github.com/stretchr/testify/require"
)

func TestRFC6975AlgorithmUnderstood(t *testing.T) {
	t.Parallel()

	dau, err := wire.NewAlgorithmUnderstood(wire.EDNSOptionDAU, 8, 13, 15) // RSASHA256, ECDSAP256, Ed25519
	require.NoError(t, err)
	require.Equal(t, wire.EDNSOptionDAU, dau.Code())
	require.Equal(t, []byte{8, 13, 15}, dau.Data())

	dhu, err := wire.NewAlgorithmUnderstood(wire.EDNSOptionDHU, 2, 4) // SHA256, SHA384
	require.NoError(t, err)
	require.Equal(t, wire.EDNSOptionDHU, dhu.Code())

	n3u, err := wire.NewAlgorithmUnderstood(wire.EDNSOptionN3U, 1) // SHA1
	require.NoError(t, err)
	require.Equal(t, wire.EDNSOptionN3U, n3u.Code())

	_, err = wire.NewAlgorithmUnderstood(0xff, 1)
	require.Error(t, err)

	// Round-trip through Marshal/Unmarshal: a query carrying DAU survives.
	e := wire.NewEDNSBuilder().UDPSize(4096).DO(true).Option(dau).Build()
	q, err := wire.NewBuilder().
		ID(1).
		Question(wire.NewQuestion(wirebb.MustParse("example.com"), rrtype.A)).
		EDNS(e).
		Build()
	require.NoError(t, err)
	msg, err := wire.Marshal(q)
	require.NoError(t, err)
	m, err := wire.Unmarshal(msg)
	require.NoError(t, err)
	got, ok := m.EDNS()
	require.True(t, ok)
	require.Equal(t, 1, len(got.Options()))
	require.Equal(t, wire.EDNSOptionDAU, got.Options()[0].Code())
}
