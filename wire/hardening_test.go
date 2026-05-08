package wire_test

import (
	"encoding/binary"
	"runtime"
	"testing"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/stretchr/testify/require"
)

// TestUnmarshalSectionCountClamp confirms that a 12-byte header advertising
// 0xFFFF entries in every section does not cause large allocations.
// Without the clamp, this allocates ~hundreds of MB before truncating.
func TestUnmarshalSectionCountClamp(t *testing.T) {
	t.Parallel()

	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:2], 0)      // ID
	binary.BigEndian.PutUint16(hdr[2:4], 0)      // flags
	binary.BigEndian.PutUint16(hdr[4:6], 0xffff) // qdcount
	binary.BigEndian.PutUint16(hdr[6:8], 0xffff) // ancount
	binary.BigEndian.PutUint16(hdr[8:10], 0xffff)
	binary.BigEndian.PutUint16(hdr[10:12], 0xffff)

	var memBefore runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memBefore)

	_, err := wire.Unmarshal(hdr[:])
	require.Error(t, err, "claimed-but-absent records must fail to parse")

	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)
	// 4 sections × 0xFFFF × 16 bytes/Record interface ≈ 4 MB *if* unclamped.
	// With the clamp we should allocate only a handful of slots.
	delta := memAfter.TotalAlloc - memBefore.TotalAlloc
	require.Less(t, delta, uint64(1<<20),
		"single-call alloc delta %d bytes; clamp may be missing", delta)
}

// TestDNAMECompressedTargetRejected confirms that a DNAME record whose
// target uses compression-pointer encoding is rejected. RFC 6672 §3.0
// forbids compression in the DNAME target — accepting it would let
// attackers smuggle bytes that decode to one name on receipt but pack to
// different bytes on retransmission, breaking RRSIG canonicalisation.
func TestDNAMECompressedTargetRejected(t *testing.T) {
	t.Parallel()

	// Header: 0 questions, 1 answer, 0 authority, 0 additional.
	hdr := []byte{
		0x00, 0x00, // ID
		0x00, 0x00, // flags
		0x00, 0x00, // qdcount
		0x00, 0x01, // ancount = 1
		0x00, 0x00, // nscount
		0x00, 0x00, // arcount
	}
	// Answer: name=., type=DNAME(39), class=IN(1), ttl=0, rdlen=2,
	// rdata = compression pointer 0xc00c (back to offset 12, the answer's name).
	rec := []byte{
		0x00,       // owner name = root
		0x00, 0x27, // type DNAME
		0x00, 0x01, // class IN
		0x00, 0x00, 0x00, 0x00, // ttl
		0x00, 0x02, // rdlen
		0xc0, 0x0c, // pointer
	}
	_, err := wire.Unmarshal(append(hdr, rec...))
	require.Error(t, err, "DNAME with compressed target must be rejected")
}

// TestEDNSOptionLengthBounded confirms that an OPT option whose length
// claims to extend past the OPT rdata is rejected, rather than silently
// consuming bytes belonging to the next additional record.
func TestEDNSOptionLengthBounded(t *testing.T) {
	t.Parallel()

	// Build a message: header + 0 questions + 0 answers + 0 authorities + 1
	// additional (the OPT). The OPT advertises rdlen=4 but the option claims
	// length=10, so the option would walk past the rdata window if accepted.
	buf := []byte{
		0x00, 0x00, // ID
		0x00, 0x00, // flags
		0x00, 0x00, // qdcount
		0x00, 0x00, // ancount
		0x00, 0x00, // nscount
		0x00, 0x01, // arcount = 1
	}
	// OPT pseudo-RR: name=., type=OPT(41), class=512(udpsize), ttl=0, rdlen=4
	opt := []byte{
		0x00,       // root name
		0x00, 0x29, // type OPT
		0x02, 0x00, // class = UDPsize 512
		0x00, 0x00, 0x00, 0x00, // ttl
		0x00, 0x04, // rdlen = 4
		0x00, 0x10, // option code = padding
		0x00, 0x0a, // option length = 10 (bogus — exceeds rdata window of 4)
		// 0 bytes of option data so we _would_ consume bytes from after rdata
	}
	// Pad with extra bytes to give a tempting reframe target.
	tail := []byte{0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xca, 0xfe}
	msg := append(buf, opt...)
	msg = append(msg, tail...)

	_, err := wire.Unmarshal(msg)
	require.Error(t, err, "OPT option length must be bounded by rdata window")
}
