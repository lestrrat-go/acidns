package rdata_test

import (
	"testing"

	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// fuzzRRTypes enumerates every typed rdata variant Unpack dispatches to.
// New types added to rdata.unpackTyped should be appended here so the
// fuzzer reaches their hand-written length math; missing entries leave
// adversarial-byte coverage gaps for that type.
var fuzzRRTypes = []rrtype.Type{
	rrtype.A, rrtype.AAAA, rrtype.CNAME, rrtype.NS, rrtype.PTR, rrtype.MX,
	rrtype.TXT, rrtype.SOA, rrtype.SVCB, rrtype.HTTPS, rrtype.CAA,
	rrtype.DNSKEY, rrtype.DS, rrtype.RRSIG, rrtype.NSEC, rrtype.NSEC3,
	rrtype.NSEC3PARAM, rrtype.SRV, rrtype.NAPTR, rrtype.RP, rrtype.AFSDB,
	rrtype.X25, rrtype.ISDN, rrtype.RT, rrtype.NSAP, rrtype.NSAPPTR,
	rrtype.LOC, rrtype.APL, rrtype.IPSECKEY, rrtype.DHCID, rrtype.HIP,
	rrtype.NID, rrtype.L32, rrtype.L64, rrtype.LP, rrtype.EUI48, rrtype.EUI64,
	rrtype.URI, rrtype.ZONEMD, rrtype.RESINFO, rrtype.SPF, rrtype.SSHFP,
	rrtype.TLSA, rrtype.SMIMEA, rrtype.CSYNC, rrtype.DNAME, rrtype.HINFO,
	rrtype.KX, rrtype.CDS, rrtype.CDNSKEY, rrtype.OPENPGPKEY, rrtype.CERT,
	rrtype.AMTRELAY, rrtype.TKEY,
}

// FuzzUnpackTyped feeds each registered rdata type's unpacker arbitrary
// bytes. Per-rdata length math (HIP key/hash lengths, NSEC3 salt/hash
// lengths, NAPTR character-strings, SVCB params, etc.) is hand-written
// and the rdlen post-check in rdata.Unpack is the last line of defense
// — fuzzing exercises that line directly.
//
// Contract:
//   - Unpack must not panic on any input.
//   - On success, Pack must not panic on the round-trip.
func FuzzUnpackTyped(f *testing.F) {
	// Seed corpus: short and common adversarial shapes. Each buffer is
	// fed to every type in fuzzRRTypes during the fuzz loop, so type-
	// specific coverage comes from exercising the same bytes across
	// many unpackers rather than from per-seed type tagging.
	f.Add([]byte{1, 2, 3, 4})
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	f.Add([]byte{0})
	f.Add([]byte{4, 1, 0, 4, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xff, 0xff})    // HIP-shaped
	f.Add([]byte{1, 0, 0, 5, 4, 1, 2, 3, 4, 4, 0xaa, 0xbb, 0xcc, 0xdd, 0, 0, 0}) // NSEC3-shaped
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0})                                        // NAPTR-shaped
	f.Add([]byte{0, 1, 0, 0, 1, 0, 4, 0xc0, 0, 2, 1})                            // SVCB-shaped
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0})

	f.Fuzz(func(t *testing.T, buf []byte) {
		_ = t
		// Bound rdlen to the slice length so we never claim more than
		// what was supplied — otherwise we're testing the rdlen-window
		// guard, not the per-type unpacker.
		rdlen := len(buf)
		for _, rt := range fuzzRRTypes {
			u := wirebb.NewUnpacker(append([]byte(nil), buf...))
			rd, err := rdata.Unpack(rt, u, rdlen)
			if err != nil {
				continue
			}
			// Successful round-trip: the produced rdata must Pack
			// without panic. Output is allowed to differ from the
			// input — codecs are not required to be canonical over
			// arbitrary bytes.
			_ = rdata.Pack(rd)
		}
	})
}
