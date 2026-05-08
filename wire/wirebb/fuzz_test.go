package wirebb_test

import (
	"testing"

	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// FuzzDecodeWire feeds DecodeWire arbitrary message bytes plus an
// arbitrary starting offset. The contract: must not panic and must reject
// compression-pointer loops within bounded time.
func FuzzDecodeWire(f *testing.F) {
	// Valid corpora: a packed name plus the same name with a compression
	// pointer pointing back into it.
	p := wirebb.NewPacker(nil)
	p.Name(wirebb.MustParse("example.com"))
	f.Add(p.Bytes(), 0)

	// Compression pointer: 0xc000 | 0 — references offset 0.
	f.Add([]byte{0xc0, 0x00}, 0)

	// Pointer loop: a buffer whose only content is a pointer to itself.
	f.Add([]byte{0xc0, 0x00, 0xc0, 0x00}, 2)

	// Empty / out-of-bounds inputs.
	f.Add([]byte{}, 0)
	f.Add([]byte{0xff}, 1)
	f.Add([]byte{0x40}, 0) // first two bits 01 — RFC 6891 reserved label form

	f.Fuzz(func(_ *testing.T, msg []byte, off int) {
		if off < 0 || off > len(msg) {
			return
		}
		// We only care that the call returns. Both error and success paths
		// are acceptable; what matters is no panic and bounded time.
		_, _, _ = wirebb.DecodeWire(msg, off)
	})
}
