package wirebb_test

import (
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/lestrrat-go/acidns/wire/wirebb"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	t.Parallel()

	t.Run("simple", func(t *testing.T) {
		t.Parallel()
		n, err := wirebb.Parse("example.com")
		require.NoError(t, err)
		require.Equal(t, "example.com.", n.String())
		require.Equal(t, 2, n.NumLabels())
		require.True(t, n.IsValid())
		require.False(t, n.IsRoot())
	})

	t.Run("trailing dot", func(t *testing.T) {
		t.Parallel()
		n, err := wirebb.Parse("example.com.")
		require.NoError(t, err)
		require.Equal(t, "example.com.", n.String())
	})

	t.Run("root", func(t *testing.T) {
		t.Parallel()
		n, err := wirebb.Parse(".")
		require.NoError(t, err)
		require.Equal(t, ".", n.String())
		require.Equal(t, 0, n.NumLabels())
		require.True(t, n.IsRoot())
	})

	t.Run("case folded", func(t *testing.T) {
		t.Parallel()
		a, err := wirebb.Parse("EXAMPLE.COM")
		require.NoError(t, err)
		b, err := wirebb.Parse("example.com")
		require.NoError(t, err)
		require.True(t, a.Equal(b))
		require.Equal(t, "example.com.", a.String())
	})

	t.Run("subdomain", func(t *testing.T) {
		t.Parallel()
		n, err := wirebb.Parse("a.b.c.example.com")
		require.NoError(t, err)
		require.Equal(t, 5, n.NumLabels())
	})

	t.Run("escaped dot", func(t *testing.T) {
		t.Parallel()
		n, err := wirebb.Parse(`weird\.label.example.com`)
		require.NoError(t, err)
		require.Equal(t, 3, n.NumLabels())
		labels := slices.Collect(n.Labels())
		require.Equal(t, "weird.label", string(labels[0]))
		require.Equal(t, "example", string(labels[1]))
		require.Equal(t, "com", string(labels[2]))
	})

	t.Run("escaped decimal", func(t *testing.T) {
		t.Parallel()
		n, err := wirebb.Parse(`\032space.example.com`)
		require.NoError(t, err)
		labels := slices.Collect(n.Labels())
		require.Equal(t, " space", string(labels[0]))
	})

	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		_, err := wirebb.Parse("")
		require.Error(t, err)
	})

	t.Run("empty label", func(t *testing.T) {
		t.Parallel()
		_, err := wirebb.Parse("foo..bar")
		require.Error(t, err)
	})

	t.Run("label too long", func(t *testing.T) {
		t.Parallel()
		_, err := wirebb.Parse(strings.Repeat("a", 64) + ".example.com")
		require.Error(t, err)
	})

	t.Run("name too long", func(t *testing.T) {
		t.Parallel()
		var b strings.Builder
		for range 64 {
			b.WriteString("aaaa.")
		}
		_, err := wirebb.Parse(b.String())
		require.Error(t, err)
	})

	// Regression: a 1 MiB single-label input with no dot must fail fast,
	// without buffering proportional to the input. Before the inline
	// length-cap check, Parse appended the entire string into the label
	// buffer before flush() noticed the overflow at end-of-input,
	// allocating O(input) bytes. We probe heap growth via
	// runtime.ReadMemStats; testing.AllocsPerRun counts allocation
	// events, not size, so it can't detect the regression.
	t.Run("pathological long label fails fast", func(t *testing.T) {
		t.Parallel()
		const inputLen = 1 << 20 // 1 MiB
		s := strings.Repeat("a", inputLen)

		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		_, err := wirebb.Parse(s)
		runtime.ReadMemStats(&after)

		require.Error(t, err)
		// The label cap is 63 bytes; total heap growth attributable to
		// Parse should be well under the input length. Use a generous
		// margin (16 KiB) to absorb scheduler noise and the error value
		// allocation itself, while still being orders of magnitude
		// below the 1 MiB that the unbounded path would consume.
		grew := after.TotalAlloc - before.TotalAlloc
		require.Less(t, grew, uint64(16<<10),
			"Parse allocated %d bytes for a %d-byte pathological input; "+
				"expected O(maxLabelLen)", grew, inputLen)
	})
}

func TestEqual(t *testing.T) {
	t.Parallel()

	cases := []struct {
		a, b string
		want bool
	}{
		{"example.com", "EXAMPLE.COM", true},
		{"example.com.", "example.com", true},
		{"example.com", "example.org", false},
		{"a.example.com", "example.com", false},
		{".", ".", true},
	}
	for _, tc := range cases {
		t.Run(tc.a+"_vs_"+tc.b, func(t *testing.T) {
			t.Parallel()
			a, err := wirebb.Parse(tc.a)
			require.NoError(t, err)
			b, err := wirebb.Parse(tc.b)
			require.NoError(t, err)
			require.Equal(t, tc.want, a.Equal(b))
		})
	}

	t.Run("zero values equal", func(t *testing.T) {
		t.Parallel()
		var a, b wirebb.Name
		require.True(t, a.Equal(b))
		require.False(t, a.IsValid())
	})
}

func TestParent(t *testing.T) {
	t.Parallel()

	n := wirebb.MustParse("a.b.example.com")
	steps := []string{"b.example.com.", "example.com.", "com.", "."}
	for _, want := range steps {
		p, ok := n.Parent()
		require.True(t, ok)
		require.Equal(t, want, p.String())
		n = p
	}
	_, ok := n.Parent()
	require.False(t, ok)
}

func TestFromLabels(t *testing.T) {
	t.Parallel()

	n, err := wirebb.FromLabels("www", "example", "com")
	require.NoError(t, err)
	require.Equal(t, "www.example.com.", n.String())

	n, err = wirebb.FromLabels()
	require.NoError(t, err)
	require.True(t, n.IsRoot())

	_, err = wirebb.FromLabels("", "example")
	require.Error(t, err)

	_, err = wirebb.FromLabels(strings.Repeat("a", 64))
	require.Error(t, err)
}

func TestAppendWire(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		want []byte
	}{
		{"example.com", []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}},
		{".", []byte{0}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			n := wirebb.MustParse(tc.name)
			got := n.AppendWire(nil)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestDecodeWire(t *testing.T) {
	t.Parallel()

	t.Run("simple", func(t *testing.T) {
		t.Parallel()
		buf := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0xff}
		n, off, err := wirebb.DecodeWire(buf, 0)
		require.NoError(t, err)
		require.Equal(t, "example.com.", n.String())
		require.Equal(t, 13, off)
	})

	t.Run("root", func(t *testing.T) {
		t.Parallel()
		buf := []byte{0}
		n, off, err := wirebb.DecodeWire(buf, 0)
		require.NoError(t, err)
		require.True(t, n.IsRoot())
		require.Equal(t, 1, off)
	})

	t.Run("compression pointer", func(t *testing.T) {
		t.Parallel()
		// Layout:
		// [0..12]: "example.com" wire
		// [13..]: "www" + ptr to offset 0
		buf := []byte{
			7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
			3, 'w', 'w', 'w', 0xc0, 0,
		}
		n, off, err := wirebb.DecodeWire(buf, 13)
		require.NoError(t, err)
		require.Equal(t, "www.example.com.", n.String())
		require.Equal(t, 19, off)
	})

	t.Run("pointer loop", func(t *testing.T) {
		t.Parallel()
		buf := []byte{0xc0, 0x02, 0xc0, 0x00}
		_, _, err := wirebb.DecodeWire(buf, 0)
		require.Error(t, err)
	})

	t.Run("forward pointer", func(t *testing.T) {
		t.Parallel()
		buf := []byte{0xc0, 0x02, 3, 'a', 'b', 'c', 0}
		_, _, err := wirebb.DecodeWire(buf, 0)
		require.Error(t, err)
	})

	t.Run("truncated", func(t *testing.T) {
		t.Parallel()
		buf := []byte{7, 'e', 'x'}
		_, _, err := wirebb.DecodeWire(buf, 0)
		require.Error(t, err)
	})

	t.Run("bad label length", func(t *testing.T) {
		t.Parallel()
		// 0x80 is reserved (top bits 10)
		buf := []byte{0x80, 0, 0}
		_, _, err := wirebb.DecodeWire(buf, 0)
		require.Error(t, err)
	})
}

func TestRoundTrip(t *testing.T) {
	t.Parallel()

	names := []string{".", "com", "example.com", "a.b.c.d.example.com"}
	for _, s := range names {
		t.Run(s, func(t *testing.T) {
			t.Parallel()
			n := wirebb.MustParse(s)
			buf := n.AppendWire(nil)
			n2, _, err := wirebb.DecodeWire(buf, 0)
			require.NoError(t, err)
			require.True(t, n.Equal(n2))
		})
	}
}
