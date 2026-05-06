package dnssec

import (
	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
)

// SignedDataForTest exposes signedData for use in external tests when
// constructing valid RRSIGs from generated keys.
func SignedDataForTest(set []dnsmsg.Record, r rdata.RRSIG) ([]byte, error) {
	return signedData(set, r)
}
