package ddr_test

import (
	"testing"

	"github.com/lestrrat-go/acidns/ddr"
	"github.com/stretchr/testify/require"
)

func TestProtocolString(t *testing.T) {
	t.Parallel()
	require.Equal(t, "dot", ddr.ProtoDoT.String())
	require.Equal(t, "doh", ddr.ProtoDoH.String())
	require.Equal(t, "doq", ddr.ProtoDoQ.String())
	require.Equal(t, "unknown", ddr.ProtoUnknown.String())
	require.Equal(t, "unknown", ddr.Protocol(99).String())
}
