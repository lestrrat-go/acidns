package wire_test

import (
	"errors"
	"testing"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/stretchr/testify/require"
)

func TestMessageParseError_IsCompat(t *testing.T) {
	t.Parallel()
	// Unmarshalling a too-short buffer must surface a typed
	// MessageParseError that still satisfies errors.Is(err, ErrInvalidMessage).
	_, err := wire.Unpack([]byte{1, 2, 3})
	require.Error(t, err)
	require.True(t, errors.Is(err, wire.ErrInvalidMessage),
		"errors.Is must continue to match ErrInvalidMessage for legacy callers")

	var pe *wire.MessageParseError
	require.True(t, errors.As(err, &pe), "errors.As should reach MessageParseError")
	require.Equal(t, wire.SectionHeader, pe.Section())
	require.Equal(t, -1, pe.Index())
}

func TestSection_String(t *testing.T) {
	t.Parallel()
	require.Equal(t, "header", wire.SectionHeader.String())
	require.Equal(t, "question", wire.SectionQuestion.String())
	require.Equal(t, "answer", wire.SectionAnswer.String())
	require.Equal(t, "authority", wire.SectionAuthority.String())
	require.Equal(t, "additional", wire.SectionAdditional.String())
	require.Equal(t, "opt", wire.SectionOPT.String())
	require.Equal(t, "unknown", wire.SectionUnknown.String())
}

func TestMessageParseError_ErrorString(t *testing.T) {
	t.Parallel()
	e := wire.NewMessageParseError(
		wire.SectionAnswer, 3, 47,
		errors.New("name truncated"),
	)
	got := e.Error()
	// Must mention section, index, offset, and cause.
	require.Contains(t, got, "answer")
	require.Contains(t, got, "[3]")
	require.Contains(t, got, "47")
	require.Contains(t, got, "name truncated")
}
