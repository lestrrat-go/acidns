package dnssec

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
)

// canonicalRRSet produces the byte stream defined by RFC 4034 §6.3 for an
// RRset signed by rrsig: RRs sorted in canonical order, each rendered with
// canonical owner (lowercase wire), the RRSIG's OriginalTTL, and the
// canonical form of any embedded names.
//
// Pre-condition: every record in set has the same owner/type/class.
func canonicalRRSet(set []wire.Record, rrsig rdata.RRSIG) ([]byte, error) {
	if len(set) == 0 {
		return nil, fmt.Errorf("dnssec: empty rrset")
	}
	owner := canonicalOwner(set[0].Name(), rrsig)
	class := uint16(set[0].Class())
	rrType := uint16(set[0].Type())
	origTTL := uint32(rrsig.OriginalTTL().Seconds())

	canonRDataList := make([][]byte, len(set))
	for i, r := range set {
		canonRDataList[i] = canonicalRData(r.RData())
	}
	// Sort by canonical RDATA (RFC 4034 §6.3).
	sort.SliceStable(canonRDataList, func(i, j int) bool {
		return bytes.Compare(canonRDataList[i], canonRDataList[j]) < 0
	})

	var buf bytes.Buffer
	for _, rd := range canonRDataList {
		buf.Write(owner)
		var hdr [10]byte
		binary.BigEndian.PutUint16(hdr[0:], rrType)
		binary.BigEndian.PutUint16(hdr[2:], class)
		binary.BigEndian.PutUint32(hdr[4:], origTTL)
		binary.BigEndian.PutUint16(hdr[8:], uint16(len(rd)))
		buf.Write(hdr[:])
		buf.Write(rd)
	}
	return buf.Bytes(), nil
}

// canonicalOwner returns the lowercase wire form of the owner. RFC 4034
// §3.1.3 specifies that wildcard-synthesised RRs MUST be reconstructed
// with the wildcard owner (not the QNAME) for signing — but the validator
// is given the response RR, so we reconstruct only when the rrsig's
// labels count is smaller than the owner's label count.
func canonicalOwner(owner wire.Name, rrsig rdata.RRSIG) []byte {
	rrsigLabels := int(rrsig.Labels())
	if rrsigLabels > 0 && rrsigLabels < owner.NumLabels() {
		// Replace the leading labels with a single "*" — wildcard reconstruction.
		stripped := stripLeadingLabels(owner, owner.NumLabels()-rrsigLabels)
		labels := []string{"*"}
		for l := range stripped.Labels() {
			labels = append(labels, string(l))
		}
		if star, err := wire.NameFromLabels(labels...); err == nil {
			return star.AppendWire(nil)
		}
	}
	return owner.AppendWire(nil)
}

func stripLeadingLabels(n wire.Name, count int) wire.Name {
	cur := n
	for range count {
		parent, ok := cur.Parent()
		if !ok {
			return cur
		}
		cur = parent
	}
	return cur
}

// canonicalRData returns the canonical-form RDATA bytes for r — names
// inside the RDATA are lowercased and uncompressed per RFC 4034 §6.2.
//
// The explicit cases below exist because rdata.Pack for some types
// (e.g. SOA) emits length-tagged compressed names via the
// caller-supplied [wirebb.Packer]'s compression table — we override
// here with NameUncompressed-equivalent bytes to satisfy canonical
// form. For types not listed, the default branch relies on the
// [wirebb.Name] invariant that names are stored as their lowercase
// wire encoding (every Name entry point — Parse, FromLabels,
// DecodeWire, DecodeWireUncompressed — folds ASCII case via
// foldByte). Embedded names that route through Name's AppendWire
// therefore already emit canonical bytes; types like
// DNAME/RP/AFSDB/RT/KX/SRV/NAPTR/NSEC use NameUncompressed-style
// packing and are canonical-safe through this fallback.
func canonicalRData(rd rdata.RData) []byte {
	switch v := rd.(type) {
	case rdata.NS:
		return v.Target().AppendWire(nil)
	case rdata.CNAME:
		return v.Target().AppendWire(nil)
	case rdata.PTR:
		return v.Target().AppendWire(nil)
	case rdata.SOA:
		var buf bytes.Buffer
		buf.Write(v.MName().AppendWire(nil))
		buf.Write(v.RName().AppendWire(nil))
		var nums [20]byte
		binary.BigEndian.PutUint32(nums[0:], v.Serial())
		binary.BigEndian.PutUint32(nums[4:], uint32(v.Refresh().Seconds()))
		binary.BigEndian.PutUint32(nums[8:], uint32(v.Retry().Seconds()))
		binary.BigEndian.PutUint32(nums[12:], uint32(v.Expire().Seconds()))
		binary.BigEndian.PutUint32(nums[16:], uint32(v.Minimum().Seconds()))
		buf.Write(nums[:])
		return buf.Bytes()
	case rdata.MX:
		var pref [2]byte
		binary.BigEndian.PutUint16(pref[:], v.Preference())
		return append(pref[:], v.Exchange().AppendWire(nil)...)
	default:
		// Types without compressible names: rdata.Pack already emits
		// uncompressed wire bytes (the packer's compression table is
		// fresh and only one rdata is encoded).
		return rdata.Pack(rd)
	}
}

// rrsigSignedHeader serialises the RRSIG RDATA up to (but not including)
// the signature field — the prefix that the signer fed into the algorithm.
func rrsigSignedHeader(r rdata.RRSIG) []byte {
	var hdr [18]byte
	binary.BigEndian.PutUint16(hdr[0:], uint16(r.TypeCovered()))
	hdr[2] = uint8(r.Algorithm())
	hdr[3] = r.Labels()
	binary.BigEndian.PutUint32(hdr[4:], uint32(r.OriginalTTL().Seconds()))
	binary.BigEndian.PutUint32(hdr[8:], uint32(r.SignatureExpiration().Unix()))
	binary.BigEndian.PutUint32(hdr[12:], uint32(r.SignatureInception().Unix()))
	binary.BigEndian.PutUint16(hdr[16:], r.KeyTag())
	out := make([]byte, 0, 18+r.SignerName().WireLen())
	out = append(out, hdr[:]...)
	out = append(out, r.SignerName().AppendWire(nil)...)
	return out
}

// signedData returns the bytes a verifier hashes against the RRSIG.
func signedData(set []wire.Record, r rdata.RRSIG) ([]byte, error) {
	hdr := rrsigSignedHeader(r)
	body, err := canonicalRRSet(set, r)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(hdr)+len(body))
	out = append(out, hdr...)
	out = append(out, body...)
	return out, nil
}
