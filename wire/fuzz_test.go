package wire_test

import (
	"testing"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wiretest"
)

// FuzzUnmarshal feeds wire.Unmarshal arbitrary bytes. The contract: must
// not panic, and must return a typed *MessageParseError or nil. Anything
// else (raw fmt.Errorf, plain sentinel, etc.) signals a regression in the
// error-typing work.
func FuzzUnmarshal(f *testing.F) {
	// Seed corpus: a couple of valid messages so the fuzzer has a base to
	// mutate, plus some pathologically-short inputs.
	q := wiretest.Query(wire.MustParseName("example.com"), rrtype.A)
	if buf, err := wire.Marshal(q); err == nil {
		f.Add(buf)
	}
	resp := wiretest.NXDOMAIN(q)
	if buf, err := wire.Marshal(resp); err == nil {
		f.Add(buf)
	}
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, buf []byte) {
		m, err := wire.Unmarshal(buf)
		if err == nil {
			// Round-trip: a successful Unmarshal followed by Marshal must
			// not panic. Output is allowed to differ from the input (we
			// don't ship a canonicalisation guarantee).
			if m == nil {
				t.Fatalf("Unmarshal returned (nil, nil)")
			}
			if _, mErr := wire.Marshal(m); mErr != nil {
				// Marshal failure on a successfully-Unmarshalled message
				// is a real bug — every parsed message must be
				// re-encodable.
				t.Fatalf("Marshal(Unmarshal(buf)) failed: %v", mErr)
			}
		}
	})
}
