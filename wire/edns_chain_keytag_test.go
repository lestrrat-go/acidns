package wire_test

import (
	"testing"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/stretchr/testify/require"
)

func TestChain_RoundTrip(t *testing.T) {
	t.Parallel()
	tp := wire.MustParseName("example.com")
	opt := wire.NewChain(tp)
	require.Equal(t, wire.EDNSOptionChain, opt.Code())

	got, ok := wire.ChainClosestTrustPoint(opt)
	require.True(t, ok)
	require.Equal(t, tp, got)
}

func TestChain_DecodeWrongCode(t *testing.T) {
	t.Parallel()
	notChain := wire.NewNSID([]byte("nope"))
	_, ok := wire.ChainClosestTrustPoint(notChain)
	require.False(t, ok)
}

func TestKeyTag_RoundTrip(t *testing.T) {
	t.Parallel()
	in := []uint16{19036, 20326, 12345}
	opt := wire.NewKeyTag(in...)
	require.Equal(t, wire.EDNSOptionKeyTag, opt.Code())
	require.Len(t, opt.Data(), 6)

	got, ok := wire.KeyTags(opt)
	require.True(t, ok)
	require.Equal(t, in, got)
}

func TestKeyTag_Empty(t *testing.T) {
	t.Parallel()
	opt := wire.NewKeyTag()
	got, ok := wire.KeyTags(opt)
	require.True(t, ok)
	require.Empty(t, got)
}

func TestKeyTag_DecodeWrongCode(t *testing.T) {
	t.Parallel()
	_, ok := wire.KeyTags(wire.NewNSID(nil))
	require.False(t, ok)
}
