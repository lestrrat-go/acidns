package dnssec

import (
	"crypto/sha1" //nolint:gosec // SHA-1 still required by DS digest type 1.
	"crypto/sha256"
	"crypto/sha512"
	"fmt"

	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsname"
)

// SignedData returns the canonical RRSIG signed-data payload for set under
// rrsig (RFC 4034 §3.1.8.1): the RRSIG fields with an empty signature
// followed by the canonicalised RRset. Callers feed this into the chosen
// signature algorithm; cf. Verify which performs the matching check.
func SignedData(set []dnsmsg.Record, rrsig rdata.RRSIG) ([]byte, error) {
	return signedData(set, rrsig)
}

// DSDigest computes the DS rdata digest field for owner/key under the
// requested digest type (RFC 4034 §5.1.4 / RFC 4509). Returns an error if
// the digest type is unsupported.
func DSDigest(owner dnsname.Name, key rdata.DNSKEY, dt rdata.DSDigestType) ([]byte, error) {
	data := append([]byte(nil), owner.AppendWire(nil)...)
	data = append(data, dnskeyWire(key)...)
	switch dt {
	case rdata.DigestSHA1:
		h := sha1.Sum(data) //nolint:gosec
		return h[:], nil
	case rdata.DigestSHA256:
		h := sha256.Sum256(data)
		return h[:], nil
	case rdata.DigestSHA384:
		h := sha512.Sum384(data)
		return h[:], nil
	default:
		return nil, fmt.Errorf("%w: DS digest type %d", ErrUnsupportedAlgorithm, dt)
	}
}
