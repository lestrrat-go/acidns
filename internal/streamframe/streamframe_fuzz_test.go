package streamframe_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/lestrrat-go/acidns/internal/streamframe"
	"github.com/lestrrat-go/acidns/internal/wiretest"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// FuzzReadFrame feeds streamframe.ReadFrame arbitrary bytes. The contract:
// must not panic. Both successful decodes and parse errors are allowed
// outcomes — the framing layer routinely meets garbage from peer
// connections and our job is to fail cleanly, not crash.
func FuzzReadFrame(f *testing.F) {
	// Seed: a couple of valid framed packets built via WriteFrame, so the
	// fuzzer has shape it can mutate.
	q, err := wiretest.Query(wire.MustParseName("example.com"), rrtype.A)
	if err != nil {
		f.Fatal(err)
	}
	var buf bytes.Buffer
	if err := streamframe.WriteFrame(&buf, q); err == nil {
		f.Add(buf.Bytes())
	}
	resp, err := wiretest.NXDOMAIN(q)
	if err != nil {
		f.Fatal(err)
	}
	buf.Reset()
	if err := streamframe.WriteFrame(&buf, resp); err == nil {
		f.Add(buf.Bytes())
	}

	// Seed: malformed frames the parser should reject without panicking.
	f.Add([]byte{})                       // EOF before any header byte
	f.Add([]byte{0x00})                   // truncated header (1 of 2 bytes)
	f.Add([]byte{0x00, 0x00})             // length=0, no body, must produce empty/invalid msg
	f.Add([]byte{0x00, 0x05, 0x01})       // length=5 but only 1 body byte
	f.Add([]byte{0xff, 0xff, 0x00, 0x00}) // length=65535 with way-too-short body

	// Seed: a frame whose declared body length exactly fills a tiny but
	// invalid DNS message — exercises the unmarshal path with bounded
	// garbage rather than exiting at the body-read stage.
	garbage := []byte{0x00, 0x0c}
	header := make([]byte, 2)
	binary.BigEndian.PutUint16(header, uint16(len(garbage)+10))
	f.Add(append(append(header, garbage...), make([]byte, 10)...))

	f.Fuzz(func(_ *testing.T, data []byte) {
		// We deliberately ignore the message and the error: any return
		// value is fine; the only failure mode the fuzzer is checking
		// for is a panic (or an OOM / runaway allocation, which would
		// surface as a timeout under the fuzz engine).
		_, _ = streamframe.ReadFrame(bytes.NewReader(data))
	})
}
