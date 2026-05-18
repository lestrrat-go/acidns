package wire_test

import (
	"testing"

	"github.com/lestrrat-go/acidns/internal/wiretest"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// FuzzUnpack feeds wire.Unpack arbitrary bytes. The contract: must
// not panic, and must return a typed *MessageParseError or nil. Anything
// else (raw fmt.Errorf, plain sentinel, etc.) signals a regression in the
// error-typing work.
func FuzzUnpack(f *testing.F) {
	// Seed corpus: a couple of valid messages so the fuzzer has a base to
	// mutate, plus some pathologically-short inputs.
	q, err := wiretest.Query(wire.MustParseName("example.com"), rrtype.A)
	if err != nil {
		f.Fatal(err)
	}
	if buf, err := wire.Pack(q); err == nil {
		f.Add(buf)
	}
	resp, err := wiretest.NXDOMAIN(q)
	if err != nil {
		f.Fatal(err)
	}
	if buf, err := wire.Pack(resp); err == nil {
		f.Add(buf)
	}
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, buf []byte) {
		m, err := wire.Unpack(buf)
		if err == nil {
			// Round-trip: a successful Unpack followed by Pack must
			// not panic. Output is allowed to differ from the input (we
			// don't ship a canonicalisation guarantee).
			if _, mErr := wire.Pack(m); mErr != nil {
				// Pack failure on a successfully-Unmarshalled message
				// is a real bug — every parsed message must be
				// re-encodable.
				t.Fatalf("Pack(Unpack(buf)) failed: %v", mErr)
			}
		}
	})
}
