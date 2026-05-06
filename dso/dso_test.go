package dso_test

import (
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dso"
	"github.com/stretchr/testify/require"
)

func TestKeepAlive(t *testing.T) {
	t.Parallel()
	tlv := dso.NewKeepAlive(30*time.Second, 5*time.Second)
	in, ka, ok := dso.KeepAlive(tlv)
	require.True(t, ok)
	require.Equal(t, 30*time.Second, in)
	require.Equal(t, 5*time.Second, ka)
}

func TestRetryDelay(t *testing.T) {
	t.Parallel()
	tlv := dso.NewRetryDelay(2 * time.Second)
	d, ok := dso.RetryDelay(tlv)
	require.True(t, ok)
	require.Equal(t, 2*time.Second, d)
}

func TestPaddingPackUnpack(t *testing.T) {
	t.Parallel()
	pad, err := dso.NewEncryptionPadding(16)
	require.NoError(t, err)
	require.Len(t, pad.Data, 16)

	m := &dso.Message{
		Primary: dso.NewKeepAlive(30*time.Second, 5*time.Second),
		Additional: []dso.TLV{pad},
	}
	wire, err := m.Pack()
	require.NoError(t, err)

	got, err := dso.Unpack(wire)
	require.NoError(t, err)
	require.Equal(t, dso.TypeKeepAlive, got.Primary.Type)
	require.Len(t, got.Additional, 1)
	require.Equal(t, dso.TypeEncryptionPadding, got.Additional[0].Type)
}
