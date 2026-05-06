// Package classless implements the RFC 2317 helper for classless
// IN-ADDR.ARPA delegation. When a reverse-DNS zone owner holds an IPv4
// prefix smaller than /24 (e.g. /25..../31), the parent /24 zone
// publishes a CNAME for every address in the sub-prefix that points
// into a sub-zone the prefix owner runs.
//
// Build the CNAMEs once at zone-authoring time; the parent zone serves
// them like any other RR.
package classless

import (
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsname"
)

// BuildDelegationCNAMEs returns the parent-zone CNAME records that
// delegate the reverse-DNS namespace for prefix to subzoneOwner.
//
// prefix MUST be an IPv4 prefix with length 25..31 (the technique does
// not apply to /24 or larger — those use straight NS delegation — and
// /32 has only one address). subzoneOwner is the FQDN under which the
// /27-owner publishes their PTR records, e.g.
// "0-31.2.0.192.in-addr.arpa.".
//
// Example for prefix 192.0.2.0/27 and subzoneOwner
// 0-31.2.0.192.in-addr.arpa.:
//
//	0.2.0.192.in-addr.arpa. CNAME 0.0-31.2.0.192.in-addr.arpa.
//	1.2.0.192.in-addr.arpa. CNAME 1.0-31.2.0.192.in-addr.arpa.
//	... (32 records total)
func BuildDelegationCNAMEs(prefix netip.Prefix, subzoneOwner dnsname.Name, ttl time.Duration) ([]dnsmsg.Record, error) {
	if !prefix.Addr().Is4() {
		return nil, fmt.Errorf("classless: prefix must be IPv4")
	}
	bits := prefix.Bits()
	if bits < 25 || bits > 31 {
		return nil, fmt.Errorf("classless: prefix length %d outside /25../31", bits)
	}

	first := prefix.Addr().As4()
	hostBits := 32 - bits
	count := 1 << hostBits
	startOctet := int(first[3])

	parentRev, err := reverseInAddr(first[0], first[1], first[2])
	if err != nil {
		return nil, err
	}

	out := make([]dnsmsg.Record, 0, count)
	for i := 0; i < count; i++ {
		oct := strconv.Itoa(startOctet + i)
		ownerStr := oct + "." + parentRev.String()
		owner, err := dnsname.Parse(ownerStr)
		if err != nil {
			return nil, err
		}
		targetStr := oct + "." + subzoneOwner.String()
		target, err := dnsname.Parse(targetStr)
		if err != nil {
			return nil, err
		}
		out = append(out, dnsmsg.NewRecord(owner, ttl, rdata.NewCNAME(target)))
	}
	return out, nil
}

// reverseInAddr returns the IN-ADDR.ARPA name of the /24 that contains
// (a, b, c, *).
func reverseInAddr(a, b, c byte) (dnsname.Name, error) {
	return dnsname.Parse(fmt.Sprintf("%d.%d.%d.in-addr.arpa", c, b, a))
}
