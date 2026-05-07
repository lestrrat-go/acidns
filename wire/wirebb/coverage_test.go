package wirebb_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/lestrrat-go/acidns/wire/wirebb"
	"github.com/stretchr/testify/require"
)

func TestZeroNameBehavior(t *testing.T) {
	t.Parallel()

	var n wirebb.Name
	require.False(t, n.IsValid())
	require.False(t, n.IsRoot())
	require.Equal(t, 0, n.NumLabels())
	require.Equal(t, "", n.String())
	require.Equal(t, 1, n.WireLen())
	require.Equal(t, []byte{0}, n.AppendWire(nil))

	// Labels iterator on zero name should yield nothing.
	count := 0
	for range n.Labels() {
		count++
	}
	require.Equal(t, 0, count)

	// Parent on invalid name returns false.
	_, ok := n.Parent()
	require.False(t, ok)
}

func TestRootNameBehavior(t *testing.T) {
	t.Parallel()

	r := wirebb.Root()
	require.True(t, r.IsValid())
	require.True(t, r.IsRoot())
	require.Equal(t, 0, r.NumLabels())
	require.Equal(t, ".", r.String())
	require.Equal(t, 1, r.WireLen())
	require.Equal(t, []byte{0}, r.AppendWire(nil))

	count := 0
	for range r.Labels() {
		count++
	}
	require.Equal(t, 0, count)
}

func TestWireLen(t *testing.T) {
	t.Parallel()

	n := wirebb.MustParse("example.com")
	require.Equal(t, 13, n.WireLen())

	require.Equal(t, 1, wirebb.Root().WireLen())
}

func TestLabelsBreakEarly(t *testing.T) {
	t.Parallel()

	n := wirebb.MustParse("a.b.c.d.example.com")
	got := []string{}
	for label := range n.Labels() {
		got = append(got, string(label))
		if len(got) == 2 {
			break
		}
	}
	require.Equal(t, []string{"a", "b"}, got)
}

func TestStringEscapes(t *testing.T) {
	t.Parallel()

	t.Run("escaped dot in label", func(t *testing.T) {
		n := wirebb.MustParse(`weird\.label.example.com`)
		require.Equal(t, `weird\.label.example.com.`, n.String())
	})

	t.Run("escaped backslash in label", func(t *testing.T) {
		n := wirebb.MustParse(`a\\b.example.com`)
		require.Equal(t, `a\\b.example.com.`, n.String())
	})

	t.Run("non printable becomes decimal escape", func(t *testing.T) {
		n, err := wirebb.FromLabels(string([]byte{0x01, 'x'}), "com")
		require.NoError(t, err)
		require.Equal(t, `\001x.com.`, n.String())
	})

	t.Run("high byte becomes decimal escape", func(t *testing.T) {
		n, err := wirebb.FromLabels(string([]byte{0xff}), "com")
		require.NoError(t, err)
		require.Equal(t, `\255.com.`, n.String())
	})
}

func TestMustParsePanics(t *testing.T) {
	t.Parallel()

	require.Panics(t, func() {
		wirebb.MustParse("")
	})

	// Sanity: success path doesn't panic.
	require.NotPanics(t, func() {
		_ = wirebb.MustParse("example.com")
	})
}

func TestParseEscapeErrors(t *testing.T) {
	t.Parallel()

	t.Run("trailing backslash", func(t *testing.T) {
		_, err := wirebb.Parse(`example.com\`)
		require.ErrorIs(t, err, wirebb.ErrInvalidName)
	})

	t.Run("truncated decimal escape", func(t *testing.T) {
		_, err := wirebb.Parse(`\12`)
		require.ErrorIs(t, err, wirebb.ErrInvalidName)
	})

	t.Run("non-digit second char in decimal escape", func(t *testing.T) {
		_, err := wirebb.Parse(`\1a2.com`)
		require.ErrorIs(t, err, wirebb.ErrInvalidName)
	})

	t.Run("non-digit third char in decimal escape", func(t *testing.T) {
		_, err := wirebb.Parse(`\12a.com`)
		require.ErrorIs(t, err, wirebb.ErrInvalidName)
	})

	t.Run("decimal escape over 255", func(t *testing.T) {
		_, err := wirebb.Parse(`\256.com`)
		require.ErrorIs(t, err, wirebb.ErrInvalidName)
	})

	t.Run("escaped non-digit ok", func(t *testing.T) {
		n, err := wirebb.Parse(`a\@b.com`)
		require.NoError(t, err)
		// '@' is 0x40, printable, so renders verbatim
		require.Equal(t, "a@b.com.", n.String())
	})
}

func TestFromLabelsLong(t *testing.T) {
	t.Parallel()

	// Build a name with many labels that pushes total > 255.
	labels := make([]string, 0)
	for range 64 {
		labels = append(labels, "aaaa")
	}
	_, err := wirebb.FromLabels(labels...)
	require.Error(t, err)
}

func TestDecodeWireErrors(t *testing.T) {
	t.Parallel()

	t.Run("offset out of range negative", func(t *testing.T) {
		_, _, err := wirebb.DecodeWire([]byte{0}, -1)
		require.Error(t, err)
	})

	t.Run("offset out of range past end", func(t *testing.T) {
		_, _, err := wirebb.DecodeWire([]byte{0}, 5)
		require.Error(t, err)
	})

	t.Run("empty msg", func(t *testing.T) {
		_, _, err := wirebb.DecodeWire(nil, 0)
		require.Error(t, err)
	})

	t.Run("truncated label content", func(t *testing.T) {
		// label length 7 but only 2 bytes follow.
		buf := []byte{7, 'a', 'b'}
		_, _, err := wirebb.DecodeWire(buf, 0)
		require.Error(t, err)
	})

	t.Run("truncated pointer second byte", func(t *testing.T) {
		// 0xc0 starts pointer but no second byte.
		buf := []byte{0xc0}
		_, _, err := wirebb.DecodeWire(buf, 0)
		require.Error(t, err)
	})

	t.Run("self pointer", func(t *testing.T) {
		// pointer at offset 0 pointing to offset 0.
		buf := []byte{0xc0, 0x00}
		_, _, err := wirebb.DecodeWire(buf, 0)
		require.Error(t, err)
	})

	t.Run("name exceeds max length via labels", func(t *testing.T) {
		// Build a buffer with concatenated labels that exceed 255 bytes total.
		var buf []byte
		// 4 labels of 63 bytes each = 4 * (1+63) = 256 bytes before terminator.
		for range 4 {
			buf = append(buf, 63)
			buf = append(buf, make([]byte, 63)...)
		}
		buf = append(buf, 0)
		_, _, err := wirebb.DecodeWire(buf, 0)
		require.Error(t, err)
	})

	t.Run("case folding in decoded labels", func(t *testing.T) {
		buf := []byte{3, 'A', 'B', 'C', 0}
		n, _, err := wirebb.DecodeWire(buf, 0)
		require.NoError(t, err)
		require.Equal(t, "abc.", n.String())
	})

	t.Run("reserved label type 0x40", func(t *testing.T) {
		buf := []byte{0x40, 0, 0}
		_, _, err := wirebb.DecodeWire(buf, 0)
		require.Error(t, err)
	})
}

func TestDecodeWirePointerHopLimit(t *testing.T) {
	t.Parallel()

	// Build a chain of pointers: each at offset 2k points to offset 2(k-1).
	// Starting offset is at the end. We want > maxPtrHops (32).
	const chainLen = 64
	buf := make([]byte, chainLen*2+1)
	// position 0: terminator (so chain ends in valid name).
	buf[0] = 0
	// pointers at 1..: each points back two bytes.
	// We'll arrange: pointer at offset (2i+1) -> offset (2i-1) for i=1..N,
	// and pointer at offset 1 -> offset 0 (the terminator).
	// Pointer is 2 bytes: 0xc0 | hi, lo
	pos := 1
	prev := 0
	starts := []int{}
	for pos+1 < len(buf) {
		buf[pos] = 0xc0 | byte(prev>>8)
		buf[pos+1] = byte(prev)
		starts = append(starts, pos)
		prev = pos
		pos += 2
	}
	// Decode starting from the last pointer; this chains backwards through all.
	last := starts[len(starts)-1]
	_, _, err := wirebb.DecodeWire(buf, last)
	require.Error(t, err)
}

func TestPackerNameZero(t *testing.T) {
	t.Parallel()

	// Packing a zero Name should write a single root terminator.
	var n wirebb.Name
	p := wirebb.NewPacker(nil)
	p.Name(n)
	require.Equal(t, []byte{0}, p.Bytes())
}

func TestPackerNameUncompressedZero(t *testing.T) {
	t.Parallel()

	var n wirebb.Name
	p := wirebb.NewPacker(nil)
	p.NameUncompressed(n)
	require.Equal(t, []byte{0}, p.Bytes())
}

func TestPackerNameRoot(t *testing.T) {
	t.Parallel()

	p := wirebb.NewPacker(nil)
	p.Name(wirebb.Root())
	require.Equal(t, []byte{0}, p.Bytes())
}

func TestPackerNameUsesPointerForSuffix(t *testing.T) {
	t.Parallel()

	p := wirebb.NewPacker(nil)
	p.Name(wirebb.MustParse("a.example.com"))
	p.Name(wirebb.MustParse("b.example.com"))
	got := p.Bytes()
	// Second name's "example.com" should be a pointer back to the first.
	// First: [1 'a' 7 'e'... 3 'c' 'o' 'm' 0]  -> 15 bytes
	// Second: [1 'b' 0xc0 0x02]                -> pointer to "example.com" at offset 2
	require.Equal(t, byte(1), got[15])
	require.Equal(t, byte('b'), got[16])
	require.Equal(t, byte(0xc0), got[17])
	require.Equal(t, byte(2), got[18])
	require.Equal(t, 19, len(got))
}

func TestUnpackerAccessors(t *testing.T) {
	t.Parallel()

	buf := []byte{1, 2, 3, 4, 5}
	u := wirebb.NewUnpacker(buf)
	require.Equal(t, 5, u.Remaining())
	require.Equal(t, 0, u.Off())
	require.Equal(t, buf, u.Msg())

	_, err := u.Uint8()
	require.NoError(t, err)
	require.Equal(t, 1, u.Off())
	require.Equal(t, 4, u.Remaining())

	u.SetOff(3)
	require.Equal(t, 3, u.Off())
	require.Equal(t, 2, u.Remaining())
}

func TestUnpackerTruncated(t *testing.T) {
	t.Parallel()

	t.Run("uint16 truncated", func(t *testing.T) {
		u := wirebb.NewUnpacker([]byte{1})
		_, err := u.Uint16()
		require.ErrorIs(t, err, wirebb.ErrTruncated)
	})

	t.Run("uint32 truncated", func(t *testing.T) {
		u := wirebb.NewUnpacker([]byte{1, 2, 3})
		_, err := u.Uint32()
		require.ErrorIs(t, err, wirebb.ErrTruncated)
	})

	t.Run("bytes truncated", func(t *testing.T) {
		u := wirebb.NewUnpacker([]byte{1, 2})
		_, err := u.Bytes(5)
		require.ErrorIs(t, err, wirebb.ErrTruncated)
	})

	t.Run("bytes negative", func(t *testing.T) {
		u := wirebb.NewUnpacker([]byte{1, 2})
		_, err := u.Bytes(-1)
		require.Error(t, err)
	})

	t.Run("char string length read fails", func(t *testing.T) {
		u := wirebb.NewUnpacker(nil)
		_, err := u.CharString()
		require.ErrorIs(t, err, wirebb.ErrTruncated)
	})

	t.Run("char string body truncated", func(t *testing.T) {
		// length=5 but only 2 bytes follow.
		u := wirebb.NewUnpacker([]byte{5, 'a', 'b'})
		_, err := u.CharString()
		require.ErrorIs(t, err, wirebb.ErrTruncated)
	})

	t.Run("name decode error propagates", func(t *testing.T) {
		// reserved label type triggers DecodeWire error.
		u := wirebb.NewUnpacker([]byte{0x80, 0, 0})
		_, err := u.Name()
		require.Error(t, err)
	})
}

func TestParseLabelExactlyMax(t *testing.T) {
	t.Parallel()

	n, err := wirebb.Parse(strings.Repeat("a", 63) + ".com")
	require.NoError(t, err)
	require.Equal(t, 2, n.NumLabels())
}

func TestFromLabelsCaseFolds(t *testing.T) {
	t.Parallel()

	n, err := wirebb.FromLabels("WWW", "Example", "COM")
	require.NoError(t, err)
	labels := slices.Collect(n.Labels())
	require.Equal(t, "www", string(labels[0]))
	require.Equal(t, "example", string(labels[1]))
	require.Equal(t, "com", string(labels[2]))
}
