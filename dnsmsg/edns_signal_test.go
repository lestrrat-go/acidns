package dnsmsg_test

import (
	"testing"

	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/stretchr/testify/require"
)

func TestRFC6975AlgorithmUnderstood(t *testing.T) {
	t.Parallel()

	dau, err := dnsmsg.NewAlgorithmUnderstood(dnsmsg.EDNSOptionDAU, 8, 13, 15) // RSASHA256, ECDSAP256, Ed25519
	require.NoError(t, err)
	require.Equal(t, dnsmsg.EDNSOptionDAU, dau.Code())
	require.Equal(t, []byte{8, 13, 15}, dau.Data())

	dhu, err := dnsmsg.NewAlgorithmUnderstood(dnsmsg.EDNSOptionDHU, 2, 4) // SHA256, SHA384
	require.NoError(t, err)
	require.Equal(t, dnsmsg.EDNSOptionDHU, dhu.Code())

	n3u, err := dnsmsg.NewAlgorithmUnderstood(dnsmsg.EDNSOptionN3U, 1) // SHA1
	require.NoError(t, err)
	require.Equal(t, dnsmsg.EDNSOptionN3U, n3u.Code())

	_, err = dnsmsg.NewAlgorithmUnderstood(0xff, 1)
	require.Error(t, err)

	// Round-trip through Marshal/Unmarshal: a query carrying DAU survives.
	e := dnsmsg.NewEDNSBuilder().UDPSize(4096).DO(true).Option(dau).Build()
	q, err := dnsmsg.NewBuilder().
		ID(1).
		Question(dnsmsg.NewQuestion(dnsname.MustParse("example.com"), rrtype.A)).
		EDNS(e).
		Build()
	require.NoError(t, err)
	wire, err := dnsmsg.Marshal(q)
	require.NoError(t, err)
	m, err := dnsmsg.Unmarshal(wire)
	require.NoError(t, err)
	got, ok := m.EDNS()
	require.True(t, ok)
	require.Equal(t, 1, len(got.Options()))
	require.Equal(t, dnsmsg.EDNSOptionDAU, got.Options()[0].Code())
}
