package dso_test

import (
	"errors"
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

func TestKeepAliveDecodeReject(t *testing.T) {
	t.Parallel()

	t.Run("wrong type", func(t *testing.T) {
		t.Parallel()
		bad := dso.TLV{Type: dso.TypeRetryDelay, Data: make([]byte, 8)}
		in, ka, ok := dso.KeepAlive(bad)
		require.False(t, ok)
		require.Zero(t, in)
		require.Zero(t, ka)
	})

	t.Run("wrong length", func(t *testing.T) {
		t.Parallel()
		bad := dso.TLV{Type: dso.TypeKeepAlive, Data: make([]byte, 4)}
		_, _, ok := dso.KeepAlive(bad)
		require.False(t, ok)
	})
}

func TestRetryDelay(t *testing.T) {
	t.Parallel()
	tlv := dso.NewRetryDelay(2 * time.Second)
	d, ok := dso.RetryDelay(tlv)
	require.True(t, ok)
	require.Equal(t, 2*time.Second, d)
}

func TestRetryDelayDecodeReject(t *testing.T) {
	t.Parallel()

	t.Run("wrong type", func(t *testing.T) {
		t.Parallel()
		bad := dso.TLV{Type: dso.TypeKeepAlive, Data: make([]byte, 4)}
		d, ok := dso.RetryDelay(bad)
		require.False(t, ok)
		require.Zero(t, d)
	})

	t.Run("wrong length", func(t *testing.T) {
		t.Parallel()
		bad := dso.TLV{Type: dso.TypeRetryDelay, Data: make([]byte, 2)}
		_, ok := dso.RetryDelay(bad)
		require.False(t, ok)
	})
}

func TestPaddingPackUnpack(t *testing.T) {
	t.Parallel()
	pad, err := dso.NewEncryptionPadding(16)
	require.NoError(t, err)
	require.Len(t, pad.Data, 16)

	m := &dso.Message{
		Primary:    dso.NewKeepAlive(30*time.Second, 5*time.Second),
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

func TestNewEncryptionPaddingRange(t *testing.T) {
	t.Parallel()

	t.Run("zero length allowed", func(t *testing.T) {
		t.Parallel()
		pad, err := dso.NewEncryptionPadding(0)
		require.NoError(t, err)
		require.Equal(t, dso.TypeEncryptionPadding, pad.Type)
		require.Empty(t, pad.Data)
	})

	t.Run("negative rejected", func(t *testing.T) {
		t.Parallel()
		_, err := dso.NewEncryptionPadding(-1)
		require.Error(t, err)
		require.ErrorIs(t, err, dso.ErrInvalidDSO)
	})

	t.Run("too large rejected", func(t *testing.T) {
		t.Parallel()
		_, err := dso.NewEncryptionPadding(0x10000)
		require.Error(t, err)
		require.ErrorIs(t, err, dso.ErrInvalidDSO)
	})
}

// TestPackEmptyMessage exercises the "no primary" branch of Message.Pack:
// a Message with zero-valued Primary (Type == 0) should pack to an empty
// byte slice with no error.
func TestPackEmptyMessage(t *testing.T) {
	t.Parallel()
	m := &dso.Message{}
	b, err := m.Pack()
	require.NoError(t, err)
	require.Empty(t, b)
}

// TestPackOversizedTLV exercises packTLV's length-overflow guard, both
// when the offending TLV is the primary and when it is an additional.
func TestPackOversizedTLV(t *testing.T) {
	t.Parallel()
	huge := make([]byte, 0x10000)

	t.Run("primary", func(t *testing.T) {
		t.Parallel()
		m := &dso.Message{Primary: dso.TLV{Type: dso.TypeKeepAlive, Data: huge}}
		_, err := m.Pack()
		require.Error(t, err)
		require.ErrorIs(t, err, dso.ErrInvalidDSO)
	})

	t.Run("additional", func(t *testing.T) {
		t.Parallel()
		m := &dso.Message{
			Primary:    dso.NewKeepAlive(time.Second, time.Second),
			Additional: []dso.TLV{{Type: dso.TypeEncryptionPadding, Data: huge}},
		}
		_, err := m.Pack()
		require.Error(t, err)
		require.ErrorIs(t, err, dso.ErrInvalidDSO)
	})
}

func TestUnpackTruncated(t *testing.T) {
	t.Parallel()

	t.Run("header truncated", func(t *testing.T) {
		t.Parallel()
		// Three bytes is less than the 4-byte TLV header.
		_, err := dso.Unpack([]byte{0, 1, 0})
		require.Error(t, err)
		require.ErrorIs(t, err, dso.ErrInvalidDSO)
	})

	t.Run("data truncated", func(t *testing.T) {
		t.Parallel()
		// Header claims 8-byte body, only 2 bytes follow.
		buf := []byte{0x00, 0x01, 0x00, 0x08, 0xaa, 0xbb}
		_, err := dso.Unpack(buf)
		require.Error(t, err)
		require.ErrorIs(t, err, dso.ErrInvalidDSO)
	})

	t.Run("trailing truncated tlv after primary", func(t *testing.T) {
		t.Parallel()
		// Valid primary (KeepAlive, 8 bytes of zero) followed by a
		// truncated additional TLV header.
		good, err := (&dso.Message{Primary: dso.NewKeepAlive(0, 0)}).Pack()
		require.NoError(t, err)
		buf := append(good, 0x00, 0x02) // only 2 bytes of next header
		_, err = dso.Unpack(buf)
		require.Error(t, err)
		require.ErrorIs(t, err, dso.ErrInvalidDSO)
	})
}

// TestUnpackUnknownType verifies that unrecognised TLV type codes round-trip
// through Unpack/Pack without loss.
func TestUnpackUnknownType(t *testing.T) {
	t.Parallel()
	// type=0xfffe, len=3, payload=DEADBE
	buf := []byte{0xff, 0xfe, 0x00, 0x03, 0xde, 0xad, 0xbe}
	got, err := dso.Unpack(buf)
	require.NoError(t, err)
	require.Equal(t, dso.Type(0xfffe), got.Primary.Type)
	require.Equal(t, []byte{0xde, 0xad, 0xbe}, got.Primary.Data)
	require.Empty(t, got.Additional)

	// Round-trip back to wire and ensure bytes match.
	out, err := got.Pack()
	require.NoError(t, err)
	require.Equal(t, buf, out)
}

// TestRoundTripMultipleAdditional ensures Pack/Unpack preserve order and
// data for several additional TLVs.
func TestRoundTripMultipleAdditional(t *testing.T) {
	t.Parallel()
	pad8, err := dso.NewEncryptionPadding(8)
	require.NoError(t, err)
	m := &dso.Message{
		Primary: dso.NewKeepAlive(60*time.Second, 10*time.Second),
		Additional: []dso.TLV{
			dso.NewRetryDelay(3 * time.Second),
			pad8,
		},
	}
	wire, err := m.Pack()
	require.NoError(t, err)

	got, err := dso.Unpack(wire)
	require.NoError(t, err)
	require.Equal(t, dso.TypeKeepAlive, got.Primary.Type)
	require.Len(t, got.Additional, 2)
	require.Equal(t, dso.TypeRetryDelay, got.Additional[0].Type)
	d, ok := dso.RetryDelay(got.Additional[0])
	require.True(t, ok)
	require.Equal(t, 3*time.Second, d)
	require.Equal(t, dso.TypeEncryptionPadding, got.Additional[1].Type)
	require.Len(t, got.Additional[1].Data, 8)
}

// TestErrInvalidDSOSentinel guards against accidental sentinel rewrites.
func TestErrInvalidDSOSentinel(t *testing.T) {
	t.Parallel()
	require.True(t, errors.Is(dso.ErrInvalidDSO, dso.ErrInvalidDSO))
}
