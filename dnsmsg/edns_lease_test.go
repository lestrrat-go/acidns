package dnsmsg_test

import (
	"encoding/binary"
	"testing"

	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/stretchr/testify/require"
)

func TestUpdateLease(t *testing.T) {
	t.Parallel()
	o := dnsmsg.NewUpdateLease(7200)
	require.Equal(t, dnsmsg.EDNSOptionUL, o.Code())
	require.Equal(t, 4, len(o.Data()))
	require.Equal(t, uint32(7200), binary.BigEndian.Uint32(o.Data()))
}

func TestLLQOption(t *testing.T) {
	t.Parallel()
	o := dnsmsg.NewLLQ(dnsmsg.LLQOpcodeSetup, dnsmsg.LLQErrNoError, 0, 7200)
	require.Equal(t, dnsmsg.EDNSOptionLLQ, o.Code())
	require.Equal(t, 18, len(o.Data()))
	require.Equal(t, uint16(1), binary.BigEndian.Uint16(o.Data()[0:2]))
	require.Equal(t, uint16(1), binary.BigEndian.Uint16(o.Data()[2:4]))
}
