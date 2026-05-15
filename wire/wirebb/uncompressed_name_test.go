package wirebb_test

import (
	"math"
	"testing"

	"github.com/lestrrat-go/acidns/wire/wirebb"
	"github.com/stretchr/testify/require"
)

// TestUncompressedNameBoundedHappyPath: a name that fits exactly inside
// the supplied rdlength decodes successfully and advances the offset
// past the on-the-wire encoding.
func TestUncompressedNameBoundedHappyPath(t *testing.T) {
	t.Parallel()
	// "example.com." encoded uncompressed = 13 bytes.
	buf := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	u := wirebb.NewUnpacker(buf)
	got, err := u.UncompressedName(len(buf))
	require.NoError(t, err)
	require.Equal(t, "example.com.", got.String())
	require.Equal(t, len(buf), u.Off(), "offset must advance past the full name")
}

// TestUncompressedNameOverrunFailsWithInvalidName: when the name
// extends past the supplied rdlength window, the inner name decoder
// runs out of input and returns ErrInvalidName (the "truncated" form).
// This is the security-critical case — without the bound, a malformed
// peer could trick the decoder into walking into adjacent rdata.
func TestUncompressedNameOverrunFailsWithInvalidName(t *testing.T) {
	t.Parallel()
	// "example.com." needs 13 bytes; supply only 8 bytes of window.
	buf := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	u := wirebb.NewUnpacker(buf)
	_, err := u.UncompressedName(8)
	require.ErrorIs(t, err, wirebb.ErrInvalidName)
}

// TestUncompressedNameRejectsCompressionPointer is the whole point of
// the "uncompressed" suffix: a name that includes a pointer must fail
// even when it would otherwise fit. RFC 3597 §4 forbids compression in
// embedded rdata names so the wire bytes round-trip canonically.
func TestUncompressedNameRejectsCompressionPointer(t *testing.T) {
	t.Parallel()
	// "example.com." (13 bytes) followed by "www" + ptr to offset 0
	// (3 bytes) — the second decode contains a 0xc0 pointer.
	buf := []byte{
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		3, 'w', 'w', 'w', 0xc0, 0,
	}
	u := wirebb.NewUnpacker(buf)
	// Skip the first plain name.
	_, err := u.UncompressedName(13)
	require.NoError(t, err)
	// Second decode at offset 13 must reject the compression pointer.
	_, err = u.UncompressedName(len(buf) - u.Off())
	require.Error(t, err, "compression pointer in uncompressed-name window must fail")
}

// TestUncompressedNameNegativeRdlengthIsUnbounded documents the
// "negative rdlength clamps to buffer end" escape hatch. Callers that
// don't have an rdata window — e.g. parsing a name standing alone at
// the end of the message — pass any negative value to opt out of the
// per-name bound.
func TestUncompressedNameNegativeRdlengthIsUnbounded(t *testing.T) {
	t.Parallel()
	buf := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	u := wirebb.NewUnpacker(buf)
	got, err := u.UncompressedName(-1)
	require.NoError(t, err)
	require.Equal(t, "example.com.", got.String())
}

// TestUncompressedNameOversizedRdlengthClampsToBuffer guarantees that
// passing an rdlength larger than the remaining buffer doesn't read
// past len(msg). The function should clamp silently rather than panic.
func TestUncompressedNameOversizedRdlengthClampsToBuffer(t *testing.T) {
	t.Parallel()
	buf := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	u := wirebb.NewUnpacker(buf)
	got, err := u.UncompressedName(len(buf) + 1000)
	require.NoError(t, err)
	require.Equal(t, "example.com.", got.String())
}

// TestUncompressedNameOverflowRdlengthClampsToBuffer guards against
// integer overflow on `u.off + rdlength`. A huge positive rdlength
// (e.g. math.MaxInt) must not wrap around to a value < u.off; the
// function should clamp to the buffer end instead.
func TestUncompressedNameOverflowRdlengthClampsToBuffer(t *testing.T) {
	t.Parallel()
	buf := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	u := wirebb.NewUnpacker(buf)
	got, err := u.UncompressedName(math.MaxInt)
	require.NoError(t, err)
	require.Equal(t, "example.com.", got.String())
}

// TestUncompressedNameZeroRdlengthRejectsBody: rdlength=0 with the
// unpacker positioned at the start of a name leaves the decoder zero
// bytes to read; it must fail rather than silently return a zero name.
func TestUncompressedNameZeroRdlengthRejectsBody(t *testing.T) {
	t.Parallel()
	buf := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	u := wirebb.NewUnpacker(buf)
	_, err := u.UncompressedName(0)
	require.Error(t, err)
	require.ErrorIs(t, err, wirebb.ErrInvalidName)
}
