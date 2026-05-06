// Package dnssec provides DNSSEC verification primitives: key-tag
// computation, RRSIG verification across the common modern algorithms
// (RSASHA256, ECDSAP256SHA256, ECDSAP384SHA384, ED25519), and DS digest
// verification. Walking a chain of trust from a fixed root anchor is
// also supported via Validator.
//
// Out of scope for this package: NSEC/NSEC3 negative-proof handling,
// algorithm-rollover state, and signing — only verification is provided.
package dnssec

import (
	"encoding/binary"

	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
)

// KeyTag computes the RFC 4034 Appendix B.1 key tag of a DNSKEY rdata.
// Algorithm 1 (RSAMD5) uses the alternative formula in B.2 — that
// algorithm is not supported by this package, so callers may treat any
// non-zero return as the modern key tag.
func KeyTag(k rdata.DNSKEY) uint16 {
	rd := dnskeyWire(k)
	var sum uint32
	for i, b := range rd {
		if i%2 == 0 {
			sum += uint32(b) << 8
		} else {
			sum += uint32(b)
		}
	}
	sum += (sum >> 16) & 0xffff
	return uint16(sum & 0xffff)
}

// dnskeyWire serialises the DNSKEY rdata in network order:
// flags(2) | protocol(1) | algorithm(1) | pubkey.
func dnskeyWire(k rdata.DNSKEY) []byte {
	out := make([]byte, 0, 4+len(k.PublicKey()))
	var hdr [4]byte
	binary.BigEndian.PutUint16(hdr[:2], k.Flags())
	hdr[2] = k.Protocol()
	hdr[3] = uint8(k.Algorithm())
	out = append(out, hdr[:]...)
	out = append(out, k.PublicKey()...)
	return out
}
