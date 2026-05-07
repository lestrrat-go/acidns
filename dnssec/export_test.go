package dnssec

import (
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
)

// SignedDataForTest exposes signedData for use in external tests when
// constructing valid RRSIGs from generated keys.
func SignedDataForTest(set []wire.Record, r rdata.RRSIG) ([]byte, error) {
	return signedData(set, r)
}
