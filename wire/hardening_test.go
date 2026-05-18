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

	_, err := wire.Unpack(hdr[:])
	require.Error(t, err, "claimed-but-absent records must fail to parse")

	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)
	// 4 sections × 0xFFFF × 16 bytes/Record interface ≈ 4 MB *if* unclamped.
	// With the clamp we should allocate only a handful of slots.
	delta := memAfter.TotalAlloc - memBefore.TotalAlloc
	require.Less(t, delta, uint64(1<<20),
		"single-call alloc delta %d bytes; clamp may be missing", delta)
}

// TestCompressedRdataNameRejected confirms that a record whose rdata
// embeds a domain name in a slot the relevant RFC says MUST be
// uncompressed (RFC 3597 §4 plus per-RR specs) is rejected if the
// sender used a compression pointer there. Accepting compressed bytes
// here would let attackers re-emit different wire bytes than the
// originator, breaking RRSIG canonicalisation.
func TestCompressedRdataNameRejected(t *testing.T) {
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

	tests := []struct {
		name   string
		rrType uint16
		rdata  []byte
	}{
		{
			// SRV: priority(2) + weight(2) + port(2) + target.
			// Target is a compression pointer back to the owner name.
			name:   "SRV",
			rrType: 33,
			rdata: []byte{
				0x00, 0x10, // priority
				0x00, 0x20, // weight
				0x00, 0x35, // port
				0xc0, 0x0c, // pointer
			},
		},
		{
			// KX: preference(2) + exchanger.
			name:   "KX",
			rrType: 36,
			rdata: []byte{
				0x00, 0x05, // preference
				0xc0, 0x0c, // pointer
			},
		},
		{
			// NAPTR: order(2)+pref(2)+flags(charstring)+services(charstring)+
			// regexp(charstring)+replacement.
			name:   "NAPTR",
			rrType: 35,
			rdata: []byte{
				0x00, 0x01, // order
				0x00, 0x02, // pref
				0x00,       // flags (empty char-string)
				0x00,       // services
				0x00,       // regexp
				0xc0, 0x0c, // replacement = pointer
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := []byte{0x00} // owner name = root
			rec = append(rec, byte(tc.rrType>>8), byte(tc.rrType))
			rec = append(rec, 0x00, 0x01)             // class IN
			rec = append(rec, 0x00, 0x00, 0x00, 0x00) // ttl
			rec = append(rec, byte(len(tc.rdata)>>8), byte(len(tc.rdata)))
			rec = append(rec, tc.rdata...)

			_, err := wire.Unpack(append(hdr, rec...))
			require.Error(t, err,
				"%s with compressed name in rdata must be rejected", tc.name)
		})
	}
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
	_, err := wire.Unpack(append(hdr, rec...))
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

	_, err := wire.Unpack(msg)
	require.Error(t, err, "OPT option length must be bounded by rdata window")
}

// TestEDNSDuplicateOptionRejected confirms that an OPT carrying two
// instances of the same option code is rejected. RFC 7873 §5.4 (Cookie)
// and RFC 7871 §6 (ECS) explicitly forbid duplicates; the parser must
// match the builder, otherwise an attacker can ship two valid-looking
// cookies and let strict / lax peers disagree on which one is in
// effect.
func TestEDNSDuplicateOptionRejected(t *testing.T) {
	t.Parallel()
	hdr := []byte{
		0x00, 0x00, // ID
		0x00, 0x00, // flags
		0x00, 0x00, // qd
		0x00, 0x00, // an
		0x00, 0x00, // ns
		0x00, 0x01, // ar
	}
	// OPT with two padding options, each empty (0 bytes data).
	opt := []byte{
		0x00,       // root
		0x00, 0x29, // OPT
		0x02, 0x00, // udpsize 512
		0x00, 0x00, 0x00, 0x00, // ttl
		0x00, 0x08, // rdlen = 8 (two 4-byte option headers)
		0x00, 0x0c, 0x00, 0x00, // padding, len 0
		0x00, 0x0c, 0x00, 0x00, // padding, len 0 (duplicate)
	}
	_, err := wire.Unpack(append(hdr, opt...))
	require.Error(t, err, "duplicate EDNS option code must be rejected")
}

// TestQuestionCompressionPointerRejected confirms that a query whose
// question section uses a compression pointer is rejected. RFC 1035
// §4.1.4 doesn't formally forbid compression in the question, but the
// real-world consensus (BIND, Unbound, Knot) rejects it; accepting it
// breaks RFC 5452 §9.3 0x20 case-echo verification because the parser
// would discard the original-case raw bytes.
func TestQuestionCompressionPointerRejected(t *testing.T) {
	t.Parallel()
	// Header + a question whose name is a single pointer back to
	// offset 12 (where the question itself begins). The pointer
	// references its own bytes; the parser must reject before the
	// loop self-references.
	msg := []byte{
		0x00, 0x00, // ID
		0x00, 0x00, // flags
		0x00, 0x01, // qd = 1
		0x00, 0x00, // an
		0x00, 0x00, // ns
		0x00, 0x00, // ar
		0xc0, 0x0c, // qname = pointer to offset 12 (self)
		0x00, 0x01, // type A
		0x00, 0x01, // class IN
	}
	_, err := wire.Unpack(msg)
	require.Error(t, err, "compressed qname must be rejected")
}
