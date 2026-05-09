package wire

import (
	"encoding/binary"

	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// NewChain builds a CHAIN query (RFC 7901). closestTrustPoint is the
// deepest name for which the requesting validator already holds a verified
// DNSKEY/DS chain — the responder may then return only the records below
// that point in subsequent referrals, saving round-trips.
func NewChain(closestTrustPoint wirebb.Name) EDNSOption {
	p := wirebb.NewPacker(nil)
	p.NameUncompressed(closestTrustPoint)
	return EDNSOption{code: EDNSOptionChain, data: p.Bytes()}
}

// ChainClosestTrustPoint decodes the closest-trust-point name from a
// CHAIN option, or returns false if o is not a CHAIN option or malformed.
func ChainClosestTrustPoint(o EDNSOption) (wirebb.Name, bool) {
	if o.Code() != EDNSOptionChain {
		return wirebb.Name{}, false
	}
	u := wirebb.NewUnpacker(o.Data())
	n, err := u.Name()
	if err != nil {
		return wirebb.Name{}, false
	}
	return n, true
}

// NewKeyTag builds an edns-key-tag option (RFC 8145). The tags identify
// the DNSKEY records the validator has cached as trust anchors, allowing
// zone operators to monitor the rollout of new keys.
func NewKeyTag(tags ...uint16) EDNSOption {
	data := make([]byte, 2*len(tags))
	for i, tag := range tags {
		binary.BigEndian.PutUint16(data[2*i:], tag)
	}
	return EDNSOption{code: EDNSOptionKeyTag, data: data}
}

// KeyTags decodes the list of key tags from an edns-key-tag option.
// Returns false if o is not an edns-key-tag option or its payload is not
// an even number of bytes.
func KeyTags(o EDNSOption) ([]uint16, bool) {
	if o.Code() != EDNSOptionKeyTag {
		return nil, false
	}
	d := o.Data()
	if len(d)%2 != 0 {
		return nil, false
	}
	out := make([]uint16, len(d)/2)
	for i := range out {
		out[i] = binary.BigEndian.Uint16(d[2*i:])
	}
	return out, true
}
